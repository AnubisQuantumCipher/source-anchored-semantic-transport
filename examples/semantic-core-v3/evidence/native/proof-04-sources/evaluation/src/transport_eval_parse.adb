package body Transport_Eval_Parse with SPARK_Mode is
   use Transport_Eval;
   use Transport_Child_Harness;

   function Word (Wire : Wire_Buffer; At_Pos : Positive) return Natural
   with Global => null, Pre => At_Pos < Max_Wire,
     Post => Word'Result <= 65_535
   is
   begin
      return Natural (Wire (At_Pos)) * 256 + Natural (Wire (At_Pos + 1));
   end Word;

   procedure Nodes_From_Wire
     (Wire : Wire_Buffer; Count : Node_Id; T : out Tree; Valid : out Boolean)
   with Global => null, Always_Terminates,
     Post => (if Valid then Well_Formed (T))
   is
      Base, Left, Right : Natural;
   begin
      T := (Count => Count, others => <>);
      Valid := False;
      for I in 1 .. Count loop
         Base := 10 + (I - 1) * 6;
         if Wire (Base + 1) > Operator'Pos (Operator'Last) then
            return;
         end if;
         T.Items (I).Op := Operator'Val (Wire (Base + 1));
         if Wire (Base + 2) /= (if T.Items (I).Op = Bound_Fact then 1 else 0) then
            return;
         end if;
         Left := Word (Wire, Base + 3);
         Right := Word (Wire, Base + 5);
         if Left > Max_Nodes or Right > Max_Nodes then
            return;
         end if;
         T.Items (I).Left := Left;
         T.Items (I).Right := Right;
         if not Typed_Node (T, I) then
            return;
         end if;
      end loop;
      Valid := Well_Formed (T);
   end Nodes_From_Wire;

   function Connected (T : Tree) return Boolean
   with Global => null, Pre => Well_Formed (T)
   is
      type Seen_Array is array (Node_Id) of Boolean;
      Seen : Seen_Array := [others => False];
   begin
      Seen (T.Count) := True;
      for I in reverse 1 .. T.Count loop
         if Seen (I) then
            if T.Items (I).Left > 0 then
               Seen (T.Items (I).Left) := True;
            end if;
            if T.Items (I).Right > 0 then
               Seen (T.Items (I).Right) := True;
            end if;
         end if;
      end loop;
      return (for all I in 1 .. T.Count => Seen (I));
   end Connected;

   procedure Read
     (Wire : Wire_Buffer; Length : Wire_Length; T : out Tree;
      Mode : out Scenario; Steps : out Step_Count;
      Parent, Child : out Scalar; Result : out Status)
   is
      Count : Natural;
      Candidate : Tree;
      Valid : Boolean;
   begin
      T := (others => <>);
      Mode := Unavailable;
      Steps := 0;
      Parent := 0;
      Child := 0;
      Result := Invalid_Model;
      if Length < 10 or else Wire (1) /= 83 or else Wire (2) /= 84 or else
        Wire (3) /= 69 or else Wire (4) /= 49
      then
         return;
      end if;
      Count := Word (Wire, 9);
      if Count not in 1 .. Max_Nodes or Length /= 10 + 6 * Count or
        Wire (5) > Scenario'Pos (Scenario'Last) or Natural (Wire (6)) > Step_Count'Last
      then
         return;
      end if;
      Nodes_From_Wire (Wire, Count, Candidate, Valid);
      if not Valid or else not Connected (Candidate) then
         return;
      end if;
      T := Candidate;
      Mode := Scenario'Val (Wire (5));
      Steps := Natural (Wire (6));
      Parent := Natural (Wire (7));
      Child := Natural (Wire (8));
      Result := Ok;
   end Read;
end Transport_Eval_Parse;

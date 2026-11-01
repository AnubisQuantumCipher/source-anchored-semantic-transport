package body Transport_Bound_Eval_Parse with SPARK_Mode is
   function Word (Wire : Frame_Buffer; At_Pos : Positive) return Natural
   with Global => null, Pre => At_Pos < Max_Frame,
     Post => Word'Result <= 65_535
   is
   begin
      return Natural (Wire (At_Pos)) * 256 + Natural (Wire (At_Pos + 1));
   end Word;

   procedure Nodes_From_Wire
     (Wire : Frame_Buffer; Count : Node_Id; T : out Tree;
      Observed : out Observations; Valid : out Boolean)
   with Global => null, Always_Terminates,
     Post => (if Valid then Well_Formed (T) and Consistent (T, Observed))
   is
      Base, Left, Right : Natural;
   begin
      T := (Count => Count, others => <>);
      Observed := [others => Unresolved];
      Valid := False;
      for I in 1 .. Count loop
         Base := Header_Size + (I - 1) * Record_Size;
         if Wire (Base + 1) > Operator'Pos (Operator'Last) or else
           Natural (Wire (Base + 2)) > Evidence_Mask'Last
         then
            return;
         end if;
         T.Items (I).Op := Operator'Val (Wire (Base + 1));
         if T.Items (I).Op /= Bound_Fact and Wire (Base + 2) /= 0 then
            return;
         end if;
         Observed (I) := Resolve_Mask (Natural (Wire (Base + 2)));
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
      Valid := Well_Formed (T) and Consistent (T, Observed);
   end Nodes_From_Wire;

   function Connected (T : Tree) return Boolean is
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
     (Wire : Frame_Buffer; Length : Frame_Length; T : out Tree;
      Observed : out Observations; Result : out Parse_Status)
   is
      Count : Natural;
      Candidate : Tree;
      Candidate_Observed : Observations;
      Valid : Boolean;
   begin
      T := (others => <>);
      Observed := [others => Unresolved];
      Result := Invalid_Frame;
      if Length < Header_Size or else
        Wire (1) /= 83 or else Wire (2) /= 84 or else
        Wire (3) /= 86 or else Wire (4) /= 49
      then
         return;
      end if;
      Count := Word (Wire, 5);
      if Count not in 1 .. Max_Nodes or else
        Length /= Header_Size + Record_Size * Count
      then
         return;
      end if;
      Nodes_From_Wire (Wire, Count, Candidate, Candidate_Observed, Valid);
      if not Valid or else not Connected (Candidate) then
         return;
      end if;
      T := Candidate;
      Observed := Candidate_Observed;
      Result := Ok;
   end Read;
end Transport_Bound_Eval_Parse;

package body Transport_Core_Parse with SPARK_Mode is
   use Transport_Eval;

   function Word (Wire : Wire_Buffer; Pos : Positive) return Natural
   with Global => null, Pre => Pos < Max_Wire,
     Post => Word'Result <= 65_535
   is
   begin
      return Natural (Wire (Pos)) * 256 + Natural (Wire (Pos + 1));
   end Word;

   procedure Read_Symbols
     (Wire : Wire_Buffer; Count : Core_Id; M : in out Finite_Model;
      Valid : out Boolean)
   with Global => null, Always_Terminates
   is
      Base : Natural;
   begin
      Valid := False;
      for I in 1 .. Count loop
         Base := 10 + 66 * (I - 1);
         if Wire (Base + 1) not in 1 .. 3 or Wire (Base + 2) > 2 then
            return;
         end if;
         M.Symbols (I).Role := Core_Symbol_Kind'Val (Wire (Base + 1));
         M.Symbols (I).Arity := Natural (Wire (Base + 2));
         for J in Core_Id loop
            if Wire (Base + 2 + J) > 1 then
               return;
            end if;
            M.Symbols (I).Domain (J) := Wire (Base + 2 + J) = 1;
         end loop;
      end loop;
      Valid := True;
   end Read_Symbols;

   procedure Read_Tuples
     (Wire : Wire_Buffer; Symbols : Core_Id; Count : Node_Ref;
      M : in out Finite_Model; Valid : out Boolean)
   with Global => null, Always_Terminates
   is
      Base : Natural;
   begin
      Valid := False;
      for I in 1 .. Count loop
         Base := 10 + 66 * Symbols + 4 * (I - 1);
         if Wire (Base + 1) > 64 or Wire (Base + 2) > 64 or
           Wire (Base + 3) > 64 or Wire (Base + 4) > 2
         then
            return;
         end if;
         M.Tuples (I) := (Natural (Wire (Base + 1)), Natural (Wire (Base + 2)),
                         Natural (Wire (Base + 3)), Fact_Truth'Val (Wire (Base + 4)));
      end loop;
      Valid := True;
   end Read_Tuples;

   procedure Read_Nodes
     (Wire : Wire_Buffer; Symbols : Core_Id; Tuples : Node_Ref;
      Count : Node_Id; T : in out Core_Tree; Valid : out Boolean)
   with Global => null, Always_Terminates
   is
      Base, Left, Right : Natural;
   begin
      Valid := False;
      for I in 1 .. Count loop
         Base := 10 + 66 * Symbols + 4 * Tuples + 9 * (I - 1);
         if Wire (Base + 1) > Core_Operator'Pos (Core_Operator'Last) or
           Wire (Base + 2) > 64 or Wire (Base + 3) > 64 or
           Wire (Base + 4) > 64 or Wire (Base + 5) > 64
         then
            return;
         end if;
         Left := Word (Wire, Base + 6);
         Right := Word (Wire, Base + 8);
         if Left > Max_Nodes or Right > Max_Nodes then
            return;
         end if;
         T.Items (I) := (Core_Operator'Val (Wire (Base + 1)),
                         Natural (Wire (Base + 2)), Natural (Wire (Base + 3)),
                         Natural (Wire (Base + 4)), Natural (Wire (Base + 5)),
                         Left, Right);
      end loop;
      Valid := True;
   end Read_Nodes;

   function Connected (T : Core_Tree; M : Finite_Model) return Boolean
   with Global => null, Pre => Well_Formed (T, M)
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
     (Wire : Wire_Buffer; Length : Wire_Length; T : out Core_Tree;
      M : out Finite_Model; Result : out Status)
   is
      Symbols, Tuples, Count : Natural;
      Candidate : Core_Tree;
      Model : Finite_Model;
      Valid : Boolean;
   begin
      T := (others => <>);
      M := (others => <>);
      Result := Invalid_Model;
      if Length < 10 or else Wire (1) /= 83 or else Wire (2) /= 84 or else
        Wire (3) /= 67 or else Wire (4) /= 51 or else Wire (6) /= 0
      then
         return;
      end if;
      Symbols := Natural (Wire (5));
      Tuples := Word (Wire, 7);
      Count := Word (Wire, 9);
      if Symbols not in 1 .. Max_Core_Symbols or Tuples > Max_Nodes or
        Count not in 1 .. Max_Nodes or
        Length /= 10 + 66 * Symbols + 4 * Tuples + 9 * Count
      then
         return;
      end if;
      Model.Symbol_Count := Symbols;
      Model.Tuple_Count := Tuples;
      Read_Symbols (Wire, Symbols, Model, Valid);
      if not Valid then return; end if;
      Read_Tuples (Wire, Symbols, Tuples, Model, Valid);
      if not Valid or else not Valid_Model (Model) then return; end if;
      Candidate.Count := Count;
      Read_Nodes (Wire, Symbols, Tuples, Count, Candidate, Valid);
      if not Valid or else not Well_Formed (Candidate, Model) or else
        not Connected (Candidate, Model)
      then
         return;
      end if;
      T := Candidate;
      M := Model;
      Result := Ok;
   end Read;
end Transport_Core_Parse;

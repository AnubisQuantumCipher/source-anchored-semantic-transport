with Ada.Text_IO;
with Transport_Eval; use Transport_Eval;
with Transport_Core_Parse;
with Transport_Types; use Transport_Types;

procedure Core_Checks with SPARK_Mode => Off is
   type Matrix is array (Fact_Truth, Fact_Truth) of Fact_Truth;
   And_Expected : constant Matrix :=
     [[Unresolved, Known_False, Unresolved],
      [Known_False, Known_False, Known_False],
      [Unresolved, Known_False, Known_True]];
   If_Expected : constant Matrix :=
     [[Unresolved, Unresolved, Known_True],
      [Known_True, Known_True, Known_True],
      [Unresolved, Known_False, Known_True]];

   procedure Truth_Tables is
      M : Finite_Model;
      T : Core_Tree;
      V : Values;
   begin
      M.Symbol_Count := 2;
      M.Symbols (1).Role := Predicate_Symbol;
      M.Symbols (2).Role := Predicate_Symbol;
      M.Tuple_Count := 2;
      T.Count := 3;
      T.Items (1) := (Core_Pred, 1, 0, 0, 0, 0, 0);
      T.Items (2) := (Core_Pred, 2, 0, 0, 0, 0, 0);
      for A in Fact_Truth loop
         for B in Fact_Truth loop
            M.Tuples (1) := (1, 0, 0, A);
            M.Tuples (2) := (2, 0, 0, B);
            T.Items (3) := (Core_And, 0, 0, 0, 0, 1, 2);
            Evaluate (T, M, V);
            pragma Assert (V (3) = Cell'(And_Expected (A, B), Unknown));
            T.Items (3).Op := Core_If;
            Evaluate (T, M, V);
            pragma Assert (V (3) = Cell'(If_Expected (A, B), Unknown));
         end loop;
      end loop;
      T.Count := 2;
      T.Items (2) := (Core_Must, 0, 0, 0, 0, 1, 0);
      for A in Fact_Truth loop
         M.Tuples (1).Truth := A;
         Evaluate (T, M, V);
         pragma Assert (V (1).Truth = A and V (2).Truth = Unresolved);
         pragma Assert (V (2).Outcome = Judge (A));
      end loop;
      T.Items (2).Left := 2;
      pragma Assert (not Well_Formed (T, M));
   end Truth_Tables;

   procedure Finite_Tables is
      M : Finite_Model;
   begin
      M.Symbol_Count := 4;
      M.Symbols (1).Role := Term_Symbol;
      M.Symbols (2).Role := Term_Symbol;
      M.Symbols (3).Role := Predicate_Symbol;
      M.Symbols (3).Arity := 1;
      M.Symbols (4).Role := Domain_Symbol;
      M.Symbols (4).Domain (1 .. 2) := [True, True];
      M.Tuple_Count := 2;
      M.Tuples (1) := (3, 1, 0, Known_True);
      M.Tuples (2) := (3, 2, 0, Known_False);
      pragma Assert (Valid_Model (M));
      pragma Assert (All_Value (M, 3, 4) = Known_False);
      pragma Assert (Some_Value (M, 3, 4) = Known_True);
      M.Tuple_Count := 1;
      pragma Assert (Lookup (M, 3, 2, 0) = Unresolved);
      pragma Assert (All_Value (M, 3, 4) = Unresolved);
      pragma Assert (Some_Value (M, 3, 4) = Known_True);
      M.Symbols (4).Domain := [others => False];
      pragma Assert (All_Value (M, 3, 4) = Known_True);
      pragma Assert (Some_Value (M, 3, 4) = Known_False);
      M.Tuple_Count := 2;
      M.Tuples (2) := (3, 1, 0, Known_False);
      pragma Assert (Valid_Model (M) and Lookup (M, 3, 1, 0) = Unresolved);
      M.Tuples (2).Truth := Unresolved;
      pragma Assert (Valid_Model (M) and Lookup (M, 3, 1, 0) = Unresolved);
      M.Tuples (2).Truth := Known_True;
      pragma Assert (not Valid_Model (M));
      M.Tuple_Count := 0;
      pragma Assert (Lookup (M, 3, 1, 0) = Unresolved);
      M.Symbols (4).Domain (3) := True;
      pragma Assert (not Valid_Model (M));
   end Finite_Tables;

   procedure Frames is
      W : Wire_Buffer := [others => 0];
      T : Core_Tree;
      M : Finite_Model;
      V : Values;
      S : Status;
      Size : constant := 10 + 66 + 4 + 18;
   begin
      W (1 .. 10) := [83, 84, 67, 51, 1, 0, 0, 1, 0, 2];
      W (11) := 2;
      W (77 .. 80) := [1, 0, 0, 2];
      W (81 .. 89) := [0, 1, 0, 0, 0, 0, 0, 0, 0];
      W (90 .. 98) := [6, 0, 0, 0, 0, 0, 1, 0, 0];
      Transport_Core_Parse.Read (W, Size, T, M, S);
      pragma Assert (S = Ok);
      Evaluate (T, M, V);
      pragma Assert (V (2) = Cell'(Unresolved, Satisfied));
      for I in 0 .. Size - 1 loop
         Transport_Core_Parse.Read (W, I, T, M, S);
         pragma Assert (S /= Ok and T.Count = 0 and M.Symbol_Count = 0);
      end loop;
      Transport_Core_Parse.Read (W, Size + 1, T, M, S);
      pragma Assert (S /= Ok);
      W (96) := 2;
      Transport_Core_Parse.Read (W, Size, T, M, S);
      pragma Assert (S /= Ok);
      W (96) := 1;
      W (80) := 3;
      Transport_Core_Parse.Read (W, Size, T, M, S);
      pragma Assert (S /= Ok);
      W (80) := 2;
      W (90) := 7;
      Transport_Core_Parse.Read (W, Size, T, M, S);
      pragma Assert (S /= Ok);
   end Frames;
begin
   Truth_Tables;
   Finite_Tables;
   Frames;
   Ada.Text_IO.Put_Line ("PASS CORE_CHECKS");
end Core_Checks;

with Transport_Eval; use Transport_Eval;
with Transport_Bound_Eval; use Transport_Bound_Eval;
with Transport_Bound_Eval_Parse; use Transport_Bound_Eval_Parse;

procedure Transport_Bound_Eval_Checks is
   T : Tree;
   Observed : Observations;
   Result : Values;
   Wire : Frame_Buffer;
   Parsed : Parse_Status;

   procedure Put_Node
     (I : Node_Id; Op : Operator; Mask : Byte; Left, Right : Node_Ref)
   is
      Base : constant Natural := Header_Size + (I - 1) * Record_Size;
   begin
      Wire (Base + 1) := Operator'Pos (Op);
      Wire (Base + 2) := Mask;
      Wire (Base + 3) := Byte (Left / 256);
      Wire (Base + 4) := Byte (Left mod 256);
      Wire (Base + 5) := Byte (Right / 256);
      Wire (Base + 6) := Byte (Right mod 256);
   end Put_Node;

   procedure Header (Count : Node_Ref) is
   begin
      Wire := [others => 0];
      Wire (1 .. 4) := [83, 84, 86, 49];
      Wire (5) := Byte (Count / 256);
      Wire (6) := Byte (Count mod 256);
   end Header;

   procedure Opposite_Frame is
   begin
      Header (5);
      Put_Node (1, Bound_Fact, 4, 0, 0);
      Put_Node (2, Bound_Fact, 2, 0, 0);
      Put_Node (3, Obligation, 0, 1, 0);
      Put_Node (4, Obligation, 0, 2, 0);
      Put_Node (5, Norm_And, 0, 3, 4);
   end Opposite_Frame;

   procedure Expect_Refused (Length : Frame_Length) is
   begin
      T := (Count => Max_Nodes, others => <>);
      Observed := [others => Known_True];
      Read (Wire, Length, T, Observed, Parsed);
      pragma Assert (Parsed = Invalid_Frame);
      pragma Assert (T = Tree'(others => <>));
      pragma Assert (for all I in Node_Id => Observed (I) = Unresolved);
   end Expect_Refused;

   procedure Check_Opposite_And_Reset is
   begin
      Opposite_Frame;
      Read (Wire, 36, T, Observed, Parsed);
      pragma Assert (Parsed = Ok and T.Count = 5);
      pragma Assert (Observed (1) = Known_True and Observed (2) = Known_False);
      Result := [others => (Known_True, Satisfied)];
      Transport_Bound_Eval.Evaluate (T, Observed, Result);
      pragma Assert (Result (1) = Cell'(Known_True, Unknown));
      pragma Assert (Result (2) = Cell'(Known_False, Unknown));
      pragma Assert (Result (3) = Cell'(Unresolved, Satisfied));
      pragma Assert (Result (4) = Cell'(Unresolved, Violated));
      pragma Assert (Result (5) = Cell'(Unresolved, Violated));
      pragma Assert (for all I in 6 .. Max_Nodes => Result (I) = Cell'(others => <>));
      Observed (1) := Unresolved;
      Observed (2) := Unresolved;
      Transport_Bound_Eval.Evaluate (T, Observed, Result);
      pragma Assert (for all I in Node_Id => Result (I) = Cell'(others => <>));
   end Check_Opposite_And_Reset;

   procedure Check_Masks is
      Expected : constant array (Evidence_Mask) of Fact_Truth :=
        [Unresolved, Unresolved, Known_False, Unresolved,
         Known_True, Unresolved, Unresolved, Unresolved];
   begin
      for Mask in Evidence_Mask loop
         pragma Assert (Resolve_Mask (Mask) = Expected (Mask));
         Header (2);
         Put_Node (1, Bound_Fact, Byte (Mask), 0, 0);
         Put_Node (2, Obligation, 0, 1, 0);
         Read (Wire, 18, T, Observed, Parsed);
         pragma Assert (Parsed = Ok and Observed (1) = Expected (Mask));
         Transport_Bound_Eval.Evaluate (T, Observed, Result);
         pragma Assert (Result (1).Truth = Expected (Mask));
         pragma Assert (Result (2).Outcome = Judge (Expected (Mask)));
      end loop;
      Put_Node (1, Bound_Fact, 8, 0, 0);
      Expect_Refused (18);
      Put_Node (1, Bound_Fact, 255, 0, 0);
      Expect_Refused (18);
   end Check_Masks;

   procedure Check_Unused_Masks is
   begin
      for Mask in Byte range 1 .. 7 loop
         Opposite_Frame;
         Put_Node (3, Obligation, Mask, 1, 0);
         Expect_Refused (36);
         Opposite_Frame;
         Put_Node (1, Unbound_Fact, Mask, 0, 0);
         Expect_Refused (36);
         Opposite_Frame;
         Put_Node (5, Norm_And, Mask, 3, 4);
         Expect_Refused (36);
      end loop;
   end Check_Unused_Masks;

   procedure Check_Maximum is
   begin
      Header (Max_Nodes);
      Put_Node (1, Bound_Fact, 4, 0, 0);
      for I in 2 .. Max_Nodes - 1 loop
         Put_Node (I, Negation, 0, I - 1, 0);
      end loop;
      Put_Node (Max_Nodes, Obligation, 0, Max_Nodes - 1, 0);
      Read (Wire, Max_Frame, T, Observed, Parsed);
      pragma Assert (Parsed = Ok and T.Count = Max_Nodes);
      Transport_Bound_Eval.Evaluate (T, Observed, Result);
      pragma Assert (Result (1).Truth = Known_True);
      pragma Assert (Result (2).Truth = Known_False);
      pragma Assert (Result (Max_Nodes).Outcome = Satisfied);
      Header (2);
      Put_Node (1, Unbound_Fact, 0, 0, 0);
      Put_Node (2, Obligation, 0, 1, 0);
      Read (Wire, 18, T, Observed, Parsed);
      pragma Assert (Parsed = Ok);
      Transport_Bound_Eval.Evaluate (T, Observed, Result);
      pragma Assert (for all I in Node_Id => Result (I) = Cell'(others => <>));
   end Check_Maximum;

   procedure Check_Structure_Refusals is
   begin
      Opposite_Frame;
      Put_Node (5, Fact_And, 0, 3, 4);
      Expect_Refused (36);
      Opposite_Frame;
      Put_Node (4, Obligation, 0, 3, 0);
      Expect_Refused (36);
      Opposite_Frame;
      Put_Node (3, Obligation, 0, 4, 0);
      Expect_Refused (36);
      Opposite_Frame;
      Put_Node (3, Obligation, 0, 3, 0);
      Expect_Refused (36);
      Opposite_Frame;
      Put_Node (4, Obligation, 0, 1, 0);
      Expect_Refused (36);
      Opposite_Frame;
      Put_Node (1, Bound_Fact, 4, 1, 0);
      Expect_Refused (36);
      Opposite_Frame;
      Wire (7) := 6;
      Expect_Refused (36);
      Opposite_Frame;
      Wire (21) := 2;
      Expect_Refused (36);
   end Check_Structure_Refusals;

   procedure Check_Length_Refusals is
   begin
      Opposite_Frame;
      for Length in Frame_Length range 0 .. 35 loop
         Expect_Refused (Length);
      end loop;
      Expect_Refused (37);
      Wire (3) := 66;
      Expect_Refused (36);
      Header (0);
      Expect_Refused (6);
      Wire (5) := 1;
      Wire (6) := 1;
      Expect_Refused (Max_Frame);
      Header (1);
      Put_Node (1, Bound_Fact, 4, 0, 0);
      Expect_Refused (12);
   end Check_Length_Refusals;

   procedure Check_Disconnected_Evaluator is
   begin
      T := (Count => 3, others => <>);
      T.Items (1) := (Bound_Fact, 0, 0);
      T.Items (2) := (Bound_Fact, 0, 0);
      T.Items (3) := (Obligation, 2, 0);
      Observed := [1 => Known_True, 2 => Known_False, others => Unresolved];
      pragma Assert (Well_Formed (T) and not Connected (T));
      Transport_Bound_Eval.Evaluate (T, Observed, Result);
      pragma Assert (Result (1).Truth = Known_True);
      pragma Assert (Result (2).Truth = Known_False);
      pragma Assert (Result (3).Outcome = Violated);
      pragma Assert (for all I in 4 .. Max_Nodes => Result (I) = Cell'(others => <>));
   end Check_Disconnected_Evaluator;
begin
   Check_Opposite_And_Reset;
   Check_Masks;
   Check_Unused_Masks;
   Check_Maximum;
   Check_Structure_Refusals;
   Check_Length_Refusals;
   Check_Disconnected_Evaluator;
end Transport_Bound_Eval_Checks;

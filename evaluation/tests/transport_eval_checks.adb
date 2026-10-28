with Transport_Eval; use Transport_Eval;

procedure Transport_Eval_Checks is
   T : Tree;
   Result : Values;
begin
   --  Well_Formed permits disconnected earlier nodes. Evaluate must still
   --  compute every node and reset every unused cell, regardless of parsing.
   T := (Count => 3, others => <>);
   T.Items (1) := (Bound_Fact, 0, 0);
   T.Items (2) := (Bound_Fact, 0, 0);
   T.Items (3) := (Obligation, 2, 0);
   pragma Assert (Well_Formed (T));
   for Observed in Fact_Truth loop
      Result := [others => (Known_True, Violated)];
      Evaluate (T, Observed, Result);
      pragma Assert (Result (1).Truth = Observed and Result (2).Truth = Observed);
      pragma Assert (Result (3).Outcome = Judge (Observed));
      pragma Assert (for all I in 4 .. Max_Nodes => Result (I) = Cell'(others => <>));
   end loop;
   T := (Count => Max_Nodes, others => <>);
   for I in 2 .. Max_Nodes - 1 loop
      T.Items (I) := (Negation, I - 1, 0);
   end loop;
   T.Items (Max_Nodes) := (Obligation, Max_Nodes - 1, 0);
   pragma Assert (Well_Formed (T));
   Evaluate (T, Unresolved, Result);
   pragma Assert (for all I in Node_Id => Result (I) = Cell'(others => <>));
end Transport_Eval_Checks;

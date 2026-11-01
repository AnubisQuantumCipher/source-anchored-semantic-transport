package body Transport_Bound_Eval with SPARK_Mode is
   procedure Preserve_Step
     (T : Tree; I : Node_Id; Observed : Fact_Truth; Before, After : Values)
   with Ghost, Global => null, Always_Terminates,
     Pre => Typed_Node (T, I) and then
       (for all J in 1 .. I - 1 => Before (J) = After (J)),
     Post => Step (T, I, Observed, Before) = Step (T, I, Observed, After)
   is
      Item : constant Node := T.Items (I);
   begin
      if Item.Op in Negation | Obligation | Fact_And | Norm_And then
         pragma Assert (Before (Item.Left) = After (Item.Left));
      end if;
      if Item.Op in Fact_And | Norm_And then
         pragma Assert (Before (Item.Right) = After (Item.Right));
      end if;
   end Preserve_Step;

   procedure Preserve_Prefix
     (T : Tree; Through : Node_Id; Observed : Observations;
      Before, After : Values)
   with Ghost, Global => null, Always_Terminates,
     Pre => Well_Formed (T) and then Through <= T.Count and then
       (for all J in 1 .. Through - 1 => Before (J) = After (J)),
     Post => (for all J in 1 .. Through => Typed_Node (T, J) and then
       Step (T, J, Observed (J), Before) = Step (T, J, Observed (J), After))
   is
   begin
      for J in 1 .. Through loop
         Preserve_Step (T, J, Observed (J), Before, After);
         pragma Loop_Invariant
           (for all K in 1 .. J => Typed_Node (T, K) and then
              Step (T, K, Observed (K), Before) =
                Step (T, K, Observed (K), After));
      end loop;
   end Preserve_Prefix;

   procedure Evaluate (T : Tree; Observed : Observations; Result : out Values) is
      Before : Values with Ghost;
   begin
      Result := [others => <>];
      for I in 1 .. T.Count loop
         Before := Result;
         Result (I) := Step (T, I, Observed (I), Result);
         Preserve_Prefix (T, I, Observed, Before, Result);
         pragma Loop_Invariant (Well_Formed (T));
         pragma Loop_Invariant
           (for all J in 1 .. I => Typed_Node (T, J) and then
              Result (J) = Step (T, J, Observed (J), Result));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Nodes => Result (J) = Cell'(others => <>));
      end loop;
   end Evaluate;
end Transport_Bound_Eval;

package body Transport_Eval with SPARK_Mode is
   function Typed_Node (T : Tree; I : Node_Id) return Boolean is
   begin
      return (case T.Items (I).Op is
        when Unbound_Fact | Bound_Fact =>
          T.Items (I).Left = 0 and T.Items (I).Right = 0,
        when Negation | Obligation =>
          T.Items (I).Left in 1 .. I - 1 and then
          T.Items (I).Right = 0 and then
          Kind (T.Items (T.Items (I).Left).Op) = Fact,
        when Fact_And | Norm_And =>
          T.Items (I).Left in 1 .. I - 1 and then
          T.Items (I).Right in 1 .. I - 1 and then
          Kind (T.Items (T.Items (I).Left).Op) = Kind (T.Items (I).Op) and then
          Kind (T.Items (T.Items (I).Right).Op) = Kind (T.Items (I).Op));
   end Typed_Node;

   function Step (T : Tree; I : Node_Id; Observed : Fact_Truth;
                  Prior : Values) return Cell is
      Item : constant Node := T.Items (I);
   begin
      case Item.Op is
         when Unbound_Fact =>
            return (others => <>);
         when Bound_Fact =>
            return (Truth => Observed, Outcome => Unknown);
         when Negation =>
            return (Truth => Negate (Prior (Item.Left).Truth), Outcome => Unknown);
         when Fact_And =>
            return (Truth => Both (Prior (Item.Left).Truth,
                                  Prior (Item.Right).Truth), Outcome => Unknown);
         when Obligation =>
            return (Truth => Unresolved, Outcome => Judge (Prior (Item.Left).Truth));
         when Norm_And =>
            return (Truth => Unresolved,
                    Outcome => Conjoin (Prior (Item.Left).Outcome,
                                        Prior (Item.Right).Outcome));
      end case;
   end Step;

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
     (T : Tree; Through : Node_Id; Observed : Fact_Truth;
      Before, After : Values)
   with Ghost, Global => null, Always_Terminates,
     Pre => Well_Formed (T) and then Through <= T.Count and then
       (for all J in 1 .. Through - 1 => Before (J) = After (J)),
     Post => (for all J in 1 .. Through => Typed_Node (T, J) and then
       Step (T, J, Observed, Before) = Step (T, J, Observed, After))
   is
   begin
      for J in 1 .. Through loop
         Preserve_Step (T, J, Observed, Before, After);
         pragma Loop_Invariant
           (for all K in 1 .. J => Typed_Node (T, K) and then
              Step (T, K, Observed, Before) = Step (T, K, Observed, After));
      end loop;
   end Preserve_Prefix;

   procedure Evaluate (T : Tree; Observed : Fact_Truth; Result : out Values) is
      Before : Values with Ghost;
   begin
      Result := [others => <>];
      for I in 1 .. T.Count loop
         Before := Result;
         Result (I) := Step (T, I, Observed, Result);
         Preserve_Prefix (T, I, Observed, Before, Result);
         pragma Loop_Invariant (Well_Formed (T));
         pragma Loop_Invariant
           (for all J in 1 .. I => Typed_Node (T, J) and then
              Result (J) = Step (T, J, Observed, Result));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Nodes => Result (J) = Cell'(others => <>));
      end loop;
   end Evaluate;
   function Typed_Node (T : Core_Tree; M : Finite_Model; I : Node_Id)
                        return Boolean is
      Item : constant Core_Node := T.Items (I);
   begin
      return (case Item.Op is
        when Core_Pred => Item.Left = 0 and Item.Right = 0 and Item.Domain = 0 and
          Valid_Call (M, Item.Predicate, Item.Arg_1, Item.Arg_2),
        when Core_All | Core_Some =>
          Item.Left = 0 and then Item.Right = 0 and then Item.Arg_1 = 0 and then
          Item.Arg_2 = 0 and then Item.Predicate in 1 .. M.Symbol_Count and then
          M.Symbols (Item.Predicate).Role = Predicate_Symbol and then
          M.Symbols (Item.Predicate).Arity = 1 and then
          Item.Domain in 1 .. M.Symbol_Count and then
          M.Symbols (Item.Domain).Role = Domain_Symbol,
        when Core_Not | Core_Must | Core_And | Core_If =>
          Item.Predicate = 0 and then Item.Arg_1 = 0 and then Item.Arg_2 = 0 and then
          Item.Domain = 0 and then Item.Left in 1 .. I - 1 and then
          Kind (T.Items (Item.Left).Op) = Fact and then
          (if Item.Op in Core_Not | Core_Must then Item.Right = 0
           else Item.Right in 1 .. I - 1 and then Kind (T.Items (Item.Right).Op) = Fact));
   end Typed_Node;

   function Step (T : Core_Tree; M : Finite_Model; I : Node_Id;
                  Prior : Values) return Cell is
      Item : constant Core_Node := T.Items (I);
   begin
      case Item.Op is
         when Core_Pred =>
            return (Lookup (M, Item.Predicate, Item.Arg_1, Item.Arg_2), Unknown);
         when Core_Not =>
            return (Negate (Prior (Item.Left).Truth), Unknown);
         when Core_And =>
            return (Both (Prior (Item.Left).Truth, Prior (Item.Right).Truth), Unknown);
         when Core_If =>
            return (Implies (Prior (Item.Left).Truth, Prior (Item.Right).Truth), Unknown);
         when Core_All =>
            return (All_Value (M, Item.Predicate, Item.Domain), Unknown);
         when Core_Some =>
            return (Some_Value (M, Item.Predicate, Item.Domain), Unknown);
         when Core_Must =>
            return (Unresolved, Judge (Prior (Item.Left).Truth));
      end case;
   end Step;

   procedure Preserve_Core_Step
     (T : Core_Tree; M : Finite_Model; I : Node_Id; Before, After : Values)
   with Ghost, Global => null, Always_Terminates,
     Pre => Typed_Node (T, M, I) and then
       (for all J in 1 .. I - 1 => Before (J) = After (J)),
     Post => Step (T, M, I, Before) = Step (T, M, I, After)
   is
      Item : constant Core_Node := T.Items (I);
   begin
      if Item.Op in Core_Not | Core_Must | Core_And | Core_If then
         pragma Assert (Before (Item.Left) = After (Item.Left));
      end if;
      if Item.Op in Core_And | Core_If then
         pragma Assert (Before (Item.Right) = After (Item.Right));
      end if;
   end Preserve_Core_Step;

   procedure Preserve_Core_Prefix
     (T : Core_Tree; M : Finite_Model; Through : Node_Id; Before, After : Values)
   with Ghost, Global => null, Always_Terminates,
     Pre => Well_Formed (T, M) and then Through <= T.Count and then
       (for all J in 1 .. Through - 1 => Before (J) = After (J)),
     Post => (for all J in 1 .. Through => Typed_Node (T, M, J) and then
       Step (T, M, J, Before) = Step (T, M, J, After))
   is
   begin
      for J in 1 .. Through loop
         Preserve_Core_Step (T, M, J, Before, After);
         pragma Loop_Invariant
           (for all K in 1 .. J => Typed_Node (T, M, K) and then
              Step (T, M, K, Before) = Step (T, M, K, After));
      end loop;
   end Preserve_Core_Prefix;

   procedure Evaluate (T : Core_Tree; M : Finite_Model; Result : out Values) is
      Before : Values with Ghost;
   begin
      Result := [others => <>];
      for I in 1 .. T.Count loop
         Before := Result;
         Result (I) := Step (T, M, I, Result);
         Preserve_Core_Prefix (T, M, I, Before, Result);
         pragma Loop_Invariant (Well_Formed (T, M));
         pragma Loop_Invariant
           (for all J in 1 .. I => Typed_Node (T, M, J) and then
              Result (J) = Step (T, M, J, Result));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Nodes => Result (J) = Cell'(others => <>));
      end loop;
   end Evaluate;
end Transport_Eval;

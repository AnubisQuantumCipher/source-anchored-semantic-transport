package Transport_Eval with SPARK_Mode is
   Max_Nodes : constant := 256;
   subtype Node_Ref is Natural range 0 .. Max_Nodes;
   subtype Node_Id is Node_Ref range 1 .. Max_Nodes;
   type Fact_Truth is (Unresolved, Known_False, Known_True);
   type Norm_Outcome is (Unknown, Satisfied, Violated);
   type Sort is (Fact, Norm);
   type Operator is
     (Unbound_Fact, Bound_Fact, Negation, Fact_And, Obligation, Norm_And);
   type Node is record
      Op : Operator := Unbound_Fact;
      Left, Right : Node_Ref := 0;
   end record;
   type Nodes is array (Node_Id) of Node;
   type Tree is record
      Count : Node_Ref := 0;
      Items : Nodes := [others => <>];
   end record;
   type Cell is record
      Truth : Fact_Truth := Unresolved;
      Outcome : Norm_Outcome := Unknown;
   end record;
   type Values is array (Node_Id) of Cell;

   function Kind (Op : Operator) return Sort is
     (if Op in Obligation | Norm_And then Norm else Fact)
   with Global => null;

   function Typed_Node (T : Tree; I : Node_Id) return Boolean
   with Global => null,
     Post => Typed_Node'Result = (case T.Items (I).Op is
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

   function Well_Formed (T : Tree) return Boolean is
     (T.Count > 0 and then Kind (T.Items (T.Count).Op) = Norm and then
      (for all I in 1 .. T.Count => Typed_Node (T, I)))
   with Global => null;

   function Negate (Value : Fact_Truth) return Fact_Truth is
     (case Value is when Known_True => Known_False,
                    when Known_False => Known_True,
                    when Unresolved => Unresolved)
   with Global => null;

   function Both (Left, Right : Fact_Truth) return Fact_Truth is
     (if Left = Known_False or Right = Known_False then Known_False
      elsif Left = Known_True and Right = Known_True then Known_True
      else Unresolved)
   with Global => null;

   function Judge (Value : Fact_Truth) return Norm_Outcome is
     (case Value is when Known_True => Satisfied,
                    when Known_False => Violated,
                    when Unresolved => Unknown)
   with Global => null;

   function Conjoin (Left, Right : Norm_Outcome) return Norm_Outcome is
     (if Left = Violated or Right = Violated then Violated
      elsif Left = Satisfied and Right = Satisfied then Satisfied else Unknown)
   with Global => null;

   function Step (T : Tree; I : Node_Id; Observed : Fact_Truth;
                  Prior : Values) return Cell
   with Global => null, Pre => Typed_Node (T, I),
     Post => Step'Result =
       (case T.Items (I).Op is
          when Unbound_Fact => Cell'(others => <>),
          when Bound_Fact => (Truth => Observed, Outcome => Unknown),
          when Negation =>
            (Truth => Negate (Prior (T.Items (I).Left).Truth), Outcome => Unknown),
          when Fact_And =>
            (Truth => Both (Prior (T.Items (I).Left).Truth,
                            Prior (T.Items (I).Right).Truth), Outcome => Unknown),
          when Obligation =>
            (Truth => Unresolved, Outcome => Judge (Prior (T.Items (I).Left).Truth)),
          when Norm_And =>
            (Truth => Unresolved,
             Outcome => Conjoin (Prior (T.Items (I).Left).Outcome,
                                 Prior (T.Items (I).Right).Outcome)));

   procedure Evaluate (T : Tree; Observed : Fact_Truth; Result : out Values)
   with Global => null, Always_Terminates, Pre => Well_Formed (T),
     Post =>
       (for all I in 1 .. T.Count =>
          Result (I) = Step (T, I, Observed, Result)) and
       (for all I in T.Count + 1 .. Max_Nodes => Result (I) = Cell'(others => <>));
end Transport_Eval;

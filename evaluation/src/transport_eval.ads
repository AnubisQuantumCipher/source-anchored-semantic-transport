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
   --  Closed grammar 3. Legacy types, operators and contracts above are unchanged.
   Max_Core_Symbols : constant := 64;
   subtype Core_Ref is Natural range 0 .. Max_Core_Symbols;
   subtype Core_Id is Core_Ref range 1 .. Max_Core_Symbols;
   subtype Core_Arity is Natural range 0 .. 2;
   type Core_Symbol_Kind is (Absent, Term_Symbol, Predicate_Symbol, Domain_Symbol);
   type Members is array (Core_Id) of Boolean;
   type Core_Symbol is record
      Role : Core_Symbol_Kind := Absent;
      Arity : Core_Arity := 0;
      Domain : Members := [others => False];
   end record;
   type Core_Symbols is array (Core_Id) of Core_Symbol;
   type Tuple_Row is record
      Predicate, Arg_1, Arg_2 : Core_Ref := 0;
      Truth : Fact_Truth := Unresolved;
   end record;
   type Tuple_Rows is array (Node_Id) of Tuple_Row;
   type Finite_Model is record
      Symbol_Count : Core_Ref := 0;
      Symbols : Core_Symbols := [others => <>];
      Tuple_Count : Node_Ref := 0;
      Tuples : Tuple_Rows := [others => <>];
   end record;
   type Core_Operator is
     (Core_Pred, Core_Not, Core_And, Core_If, Core_All, Core_Some, Core_Must);
   type Core_Node is record
      Op : Core_Operator := Core_Pred;
      Predicate, Arg_1, Arg_2, Domain : Core_Ref := 0;
      Left, Right : Node_Ref := 0;
   end record;
   type Core_Nodes is array (Node_Id) of Core_Node;
   type Core_Tree is record
      Count : Node_Ref := 0;
      Items : Core_Nodes := [others => <>];
   end record;

   function Kind (Op : Core_Operator) return Sort is
     (if Op = Core_Must then Norm else Fact) with Global => null;
   function Is_Term (M : Finite_Model; Id : Core_Ref) return Boolean is
     (Id in 1 .. M.Symbol_Count and then M.Symbols (Id).Role = Term_Symbol)
   with Global => null;
   function Valid_Call (M : Finite_Model; P, A, B : Core_Ref) return Boolean is
     (P in 1 .. M.Symbol_Count and then M.Symbols (P).Role = Predicate_Symbol
      and then (case M.Symbols (P).Arity is
        when 0 => A = 0 and B = 0,
        when 1 => Is_Term (M, A) and B = 0,
        when 2 => Is_Term (M, A) and Is_Term (M, B)))
   with Global => null;
   function Valid_Symbol (M : Finite_Model; Id : Core_Id) return Boolean is
     (M.Symbols (Id).Role /= Absent and then
      (if M.Symbols (Id).Role /= Predicate_Symbol then M.Symbols (Id).Arity = 0)
      and then (for all J in Core_Id =>
        (if M.Symbols (Id).Domain (J) then
          M.Symbols (Id).Role = Domain_Symbol and Is_Term (M, J))))
   with Global => null;
   function Valid_Model (M : Finite_Model) return Boolean is
     (M.Symbol_Count > 0 and then
      (for all I in 1 .. M.Symbol_Count => Valid_Symbol (M, I)) and then
      (for all I in 1 .. M.Tuple_Count =>
        Valid_Call (M, M.Tuples (I).Predicate, M.Tuples (I).Arg_1,
                    M.Tuples (I).Arg_2)) and then
      (for all I in 1 .. M.Tuple_Count =>
        (for all J in 1 .. I - 1 => M.Tuples (I) /= M.Tuples (J))))
   with Global => null;

   function Reports
     (M : Finite_Model; P, A, B : Core_Ref; Value : Fact_Truth) return Boolean is
     (for some I in 1 .. M.Tuple_Count =>
        M.Tuples (I) = Tuple_Row'(P, A, B, Value))
   with Global => null;
   function Lookup (M : Finite_Model; P, A, B : Core_Ref) return Fact_Truth is
     (if Reports (M, P, A, B, Unresolved) then Unresolved
      elsif Reports (M, P, A, B, Known_True) and
        not Reports (M, P, A, B, Known_False) then Known_True
      elsif Reports (M, P, A, B, Known_False) and
        not Reports (M, P, A, B, Known_True) then Known_False
      else Unresolved)
   with Global => null;
   function All_Value (M : Finite_Model; P : Core_Ref; D : Core_Id)
                      return Fact_Truth is
     (if (for all I in Core_Id =>
           (if M.Symbols (D).Domain (I) then Lookup (M, P, I, 0) = Known_True))
      then Known_True
      elsif (for some I in Core_Id => M.Symbols (D).Domain (I) and
               Lookup (M, P, I, 0) = Known_False) then Known_False
      else Unresolved)
   with Global => null;
   function Some_Value (M : Finite_Model; P : Core_Ref; D : Core_Id)
                       return Fact_Truth is
     (if (for some I in Core_Id => M.Symbols (D).Domain (I) and
             Lookup (M, P, I, 0) = Known_True) then Known_True
      elsif (for all I in Core_Id =>
        (if M.Symbols (D).Domain (I) then Lookup (M, P, I, 0) = Known_False))
      then Known_False else Unresolved)
   with Global => null;
   function Implies (Left, Right : Fact_Truth) return Fact_Truth is
     (Negate (Both (Left, Negate (Right)))) with Global => null;

   function Typed_Node (T : Core_Tree; M : Finite_Model; I : Node_Id)
                        return Boolean
   with Global => null,
     Post => Typed_Node'Result = (case T.Items (I).Op is
       when Core_Pred => T.Items (I).Left = 0 and T.Items (I).Right = 0 and
         T.Items (I).Domain = 0 and
         Valid_Call (M, T.Items (I).Predicate, T.Items (I).Arg_1, T.Items (I).Arg_2),
       when Core_All | Core_Some =>
         T.Items (I).Left = 0 and then T.Items (I).Right = 0 and then
         T.Items (I).Arg_1 = 0 and then T.Items (I).Arg_2 = 0 and then
         T.Items (I).Predicate in 1 .. M.Symbol_Count and then
         M.Symbols (T.Items (I).Predicate).Role = Predicate_Symbol and then
         M.Symbols (T.Items (I).Predicate).Arity = 1 and then
         T.Items (I).Domain in 1 .. M.Symbol_Count and then
         M.Symbols (T.Items (I).Domain).Role = Domain_Symbol,
       when Core_Not | Core_Must | Core_And | Core_If =>
         T.Items (I).Predicate = 0 and then T.Items (I).Arg_1 = 0 and then
         T.Items (I).Arg_2 = 0 and then T.Items (I).Domain = 0 and then
         T.Items (I).Left in 1 .. I - 1 and then
         Kind (T.Items (T.Items (I).Left).Op) = Fact and then
         (if T.Items (I).Op in Core_Not | Core_Must then T.Items (I).Right = 0
          else T.Items (I).Right in 1 .. I - 1 and then
            Kind (T.Items (T.Items (I).Right).Op) = Fact));
   function Well_Formed (T : Core_Tree; M : Finite_Model) return Boolean is
     (T.Count > 0 and then Valid_Model (M) and then
      (for all I in 1 .. T.Count => Typed_Node (T, M, I)))
   with Global => null;
   function Step (T : Core_Tree; M : Finite_Model; I : Node_Id;
                  Prior : Values) return Cell
   with Global => null, Pre => Typed_Node (T, M, I),
     Post => Step'Result = (case T.Items (I).Op is
        when Core_Pred =>
          (Lookup (M, T.Items (I).Predicate, T.Items (I).Arg_1,
                   T.Items (I).Arg_2), Unknown),
        when Core_Not => (Negate (Prior (T.Items (I).Left).Truth), Unknown),
        when Core_And => (Both (Prior (T.Items (I).Left).Truth,
                                Prior (T.Items (I).Right).Truth), Unknown),
        when Core_If => (Implies (Prior (T.Items (I).Left).Truth,
                                 Prior (T.Items (I).Right).Truth), Unknown),
        when Core_All =>
          (All_Value (M, T.Items (I).Predicate, T.Items (I).Domain), Unknown),
        when Core_Some =>
          (Some_Value (M, T.Items (I).Predicate, T.Items (I).Domain), Unknown),
        when Core_Must => (Unresolved, Judge (Prior (T.Items (I).Left).Truth)));
   procedure Evaluate (T : Core_Tree; M : Finite_Model; Result : out Values)
   with Global => null, Always_Terminates, Pre => Well_Formed (T, M),
     Post =>
       (for all I in 1 .. T.Count => Result (I) = Step (T, M, I, Result)) and
       (for all I in T.Count + 1 .. Max_Nodes => Result (I) = Cell'(others => <>));
end Transport_Eval;

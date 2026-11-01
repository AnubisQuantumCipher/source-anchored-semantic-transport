with Transport_Eval; use Transport_Eval;

package Transport_Bound_Eval with SPARK_Mode is
   type Observations is array (Node_Id) of Fact_Truth;
   subtype Evidence_Mask is Natural range 0 .. 7;

   function Resolve_Mask (Mask : Evidence_Mask) return Fact_Truth is
     (if Mask = 2 then Known_False elsif Mask = 4 then Known_True
      else Unresolved)
   with Global => null,
     Post =>
       (Resolve_Mask'Result = Known_False) = (Mask = 2) and
       (Resolve_Mask'Result = Known_True) = (Mask = 4) and
       (Resolve_Mask'Result = Unresolved) = (Mask not in 2 | 4);

   function Consistent (T : Tree; Observed : Observations) return Boolean is
     (for all I in Node_Id =>
        (if I > T.Count or else T.Items (I).Op /= Bound_Fact then
           Observed (I) = Unresolved))
   with Global => null;

   procedure Evaluate (T : Tree; Observed : Observations; Result : out Values)
   with Global => null, Always_Terminates,
     Pre => Well_Formed (T) and Consistent (T, Observed),
     Post =>
       (for all I in 1 .. T.Count =>
          Result (I) = Step (T, I, Observed (I), Result)) and
       (for all I in T.Count + 1 .. Max_Nodes =>
          Result (I) = Cell'(others => <>));
end Transport_Bound_Eval;

with Transport_Graphs; use Transport_Graphs;
with Transport_Types; use Transport_Types;

package Transport_Paths with SPARK_Mode is
   subtype Path_Length is Natural range 0 .. Max_Nodes;
   subtype Child_Position is Positive range 1 .. Max_Arity;
   type Path is array (Node_Id) of Child_Position;
   type Path_Trace is array (Path_Length) of Node_Ref;

   function Advance
     (G : Graph; From : Node_Ref; Position : Child_Position) return Node_Ref
   with Global => null,
     Pre => Well_Formed (G) and then From <= G.Count,
     Post => Advance'Result <= G.Count and then
       Advance'Result =
         (if From = 0 or else Position > G.Nodes (From).Degree then 0
          else G.Nodes (From).Children (Position)) and then
       (if From = 0 then Advance'Result = 0 else Advance'Result < From);

   function Trace (G : Graph; Choices : Path; Length : Path_Length)
      return Path_Trace
   with Global => null, Pre => Well_Formed (G),
     Post => Trace'Result (0) = G.Root and then
       (for all I in 0 .. Length => Trace'Result (I) <= G.Count) and then
       (for all I in 1 .. Length => Trace'Result (I) =
          Advance (G, Trace'Result (I - 1), Choices (I))) and then
       (for all I in 0 .. Length =>
          (if Trace'Result (I) > 0 then Trace'Result (I) + I <= G.Root)) and then
       (for all I in Length + 1 .. Max_Nodes => Trace'Result (I) = 0);

   function Follow (G : Graph; Choices : Path; Length : Path_Length)
      return Node_Ref
   with Global => null, Pre => Well_Formed (G),
     Post => Follow'Result = Trace (G, Choices, Length) (Length) and then
       Follow'Result <= G.Count and then
       (if Length = Max_Nodes then Follow'Result = 0);

   function Image (Map : Node_Map; Ref : Node_Ref) return Node_Ref is
     (if Ref = 0 then 0 else Map (Ref))
   with Global => null;

   function Same_Observation
     (Left : Graph; Left_At : Node_Ref; Right : Graph; Right_At : Node_Ref)
      return Boolean is
     (if Left_At = 0 or else Right_At = 0 then Left_At = Right_At
      else Left.Nodes (Left_At).Tag = Right.Nodes (Right_At).Tag and then
        Left.Nodes (Left_At).Size = Right.Nodes (Right_At).Size and then
        Left.Nodes (Left_At).Degree = Right.Nodes (Right_At).Degree and then
        (for all J in 1 .. Left.Nodes (Left_At).Size =>
          Left.Data (Left.Nodes (Left_At).First + J - 1) =
          Right.Data (Right.Nodes (Right_At).First + J - 1)))
   with Global => null,
     Pre => Well_Formed (Left) and then Well_Formed (Right) and then
       Left_At <= Left.Count and then Right_At <= Right.Count;

   procedure Prove_Path_Preservation
     (Original, Candidate : Graph; Map : Node_Map;
      Choices : Path; Length : Path_Length)
   with Ghost, Global => null, Always_Terminates,
     Pre => Preserves (Original, Candidate, Map),
     Post =>
       (for all I in 0 .. Length => Trace (Candidate, Choices, Length) (I) =
          Image (Map, Trace (Original, Choices, Length) (I))) and then
       Same_Observation
         (Original, Follow (Original, Choices, Length),
          Candidate, Follow (Candidate, Choices, Length));
end Transport_Paths;

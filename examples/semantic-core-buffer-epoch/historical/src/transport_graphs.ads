with Transport_Types; use Transport_Types;

package Transport_Graphs with SPARK_Mode is
   Max_Nodes   : constant := 1_024;
   Max_Arity   : constant := 8;
   Max_Literal : constant := 4_096;
   Last_Leaf   : constant := 6;
   Last_Op     : constant := 22;
   subtype Node_Ref is Natural range 0 .. Max_Nodes;
   subtype Node_Id is Node_Ref range 1 .. Max_Nodes;
   subtype Arity is Natural range 0 .. Max_Arity;
   subtype Literal_Size is Natural range 0 .. Max_Literal;
   subtype Literal_Start is Positive range 1 .. Max_Source + 1;
   type Child_List is array (Positive range 1 .. Max_Arity) of Node_Ref;
   type Node is record
      Tag      : Byte := 0;
      Children : Child_List := [others => 0];
      Degree   : Arity := 0;
      First    : Literal_Start := 1;
      Size     : Literal_Size := 0;
   end record;
   type Node_List is array (Node_Id) of Node;
   type Node_Map is array (Node_Id) of Node_Ref;
   type Graph is record
      Count : Node_Ref := 0;
      Root  : Node_Ref := 0;
      Used  : Source_Length := 0;
      Data  : Source_Buffer := [others => 0];
      Nodes : Node_List := [others => <>];
   end record;

   function Well_Formed (G : Graph) return Boolean is
     (G.Count > 0 and then G.Root in 1 .. G.Count and then
      (for all I in 1 .. G.Count =>
        G.Nodes (I).Tag in 1 .. Last_Op and then
        G.Nodes (I).First <= G.Used + 1 and then
        G.Nodes (I).Size <= G.Used + 1 - G.Nodes (I).First and then
        (if G.Nodes (I).Tag <= Last_Leaf then G.Nodes (I).Degree = 0
         else G.Nodes (I).Size = 0 and then G.Nodes (I).Degree > 0) and then
        (for all J in 1 .. G.Nodes (I).Degree =>
          G.Nodes (I).Children (J) in 1 .. I - 1)))
   with Global => null;

   function Valid_Map (Original, Candidate : Graph; Map : Node_Map)
      return Boolean is
     (Well_Formed (Original) and then Well_Formed (Candidate) and then
      (for all I in 1 .. Original.Count => Map (I) in 1 .. Candidate.Count))
   with Global => null;

   function Node_Preserved
     (Original, Candidate : Graph; Map : Node_Map; I : Node_Id)
      return Boolean
   with Global => null,
     Pre => Valid_Map (Original, Candidate, Map) and then I <= Original.Count,
     Post => Node_Preserved'Result =
       (Original.Nodes (I).Tag = Candidate.Nodes (Map (I)).Tag and then
        Original.Nodes (I).Size = Candidate.Nodes (Map (I)).Size and then
        Original.Nodes (I).Degree = Candidate.Nodes (Map (I)).Degree and then
        (for all J in 1 .. Original.Nodes (I).Size =>
          Original.Data (Original.Nodes (I).First + J - 1) =
          Candidate.Data (Candidate.Nodes (Map (I)).First + J - 1)) and then
        (for all J in 1 .. Original.Nodes (I).Degree =>
          Map (Original.Nodes (I).Children (J)) =
          Candidate.Nodes (Map (I)).Children (J)));

   function Preserves (Original, Candidate : Graph; Map : Node_Map)
      return Boolean is
     (Valid_Map (Original, Candidate, Map) and then
      Map (Original.Root) = Candidate.Root and then
      (for all I in 1 .. Original.Count =>
        Node_Preserved (Original, Candidate, Map, I)) and then
      (for all J in 1 .. Candidate.Count =>
        (for some I in 1 .. Original.Count => Map (I) = J)))
   with Global => null;

   procedure Check
     (Original, Candidate : Graph; Map : Node_Map; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (Result = Ok) = Preserves (Original, Candidate, Map);
end Transport_Graphs;

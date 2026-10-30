with Transport_Graphs; use Transport_Graphs;
with Transport_Paths; use Transport_Paths;
with Transport_Types; use Transport_Types;

package Transport_Graph_Parse with SPARK_Mode is
   procedure Read_Graph
     (Wire : Wire_Buffer; Length : Wire_Length;
      G : out Graph; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result = Ok then Well_Formed (G));

   procedure Read_Map
     (Wire : Wire_Buffer; Length : Wire_Length; Expected : Node_Id;
      Map : out Node_Map; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result = Ok then
       (for all I in 1 .. Expected => Map (I) > 0));

   procedure Read_Path
     (Wire : Wire_Buffer; Length : Wire_Length;
      Choices : out Path; Count : out Path_Length; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result = Ok then
       Length = 6 + Count and then
       Wire (1) = Character'Pos ('S') and then
       Wire (2) = Character'Pos ('T') and then
       Wire (3) = Character'Pos ('P') and then
       Wire (4) = Character'Pos ('1') and then
       Count = Natural (Wire (5)) * 256 + Natural (Wire (6)) and then
       (for all I in 1 .. Count => Choices (I) = Natural (Wire (6 + I))) and then
       (for all I in Count + 1 .. Max_Nodes => Choices (I) = 1)
       else Count = 0);
end Transport_Graph_Parse;

with Transport_Types; use Transport_Types;
with Transport_Graphs;

--  OS and Ada stream boundary: TESTED, outside the SPARK proof scope.
package Transport_IO with SPARK_Mode => Off is
   type Source_Command is (Decode_Source, Check_Source);
   procedure Read_Wire
     (Path : String; Wire : out Wire_Buffer; Length : out Wire_Length);
   procedure Read_Source
     (Path : String; Source : out Source_Buffer; Length : out Source_Length);
   procedure Write_Source
     (Source : Source_Buffer; Length : Source_Length);
   procedure Check_Graphs
     (Original_Path, Candidate_Path, Map_Path : String; Result : out Status);
   procedure Observe_Path
     (Graph_Path, Choices_Path : String;
      Found : out Transport_Graphs.Node_Ref; Result : out Status);
   procedure Run_Temporal (Path : String; Result : out Status);
   procedure Run_Source_Command
     (Mode : Source_Command; Wire_Path, Source_Path : String;
      Result : out Status);
end Transport_IO;

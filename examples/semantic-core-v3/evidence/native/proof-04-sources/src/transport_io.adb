with Ada.IO_Exceptions;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with GNAT.OS_Lib;
with Transport_Decoder;
with Transport_Graph_Parse;
with Transport_Paths;
with Transport_Temporal;
with Transport_Temporal_Parse;

package body Transport_IO is
   use Ada.Streams;
   package IO renames Ada.Streams.Stream_IO;

   procedure Read_Wire
     (Path : String; Wire : out Wire_Buffer; Length : out Wire_Length)
   is
      File : IO.File_Type;
      Raw  : Stream_Element_Array (1 .. Max_Wire + 1);
      Last : Stream_Element_Offset;
   begin
      Wire := [others => 0];
      Length := 0;
      IO.Open (File, IO.In_File, Path);
      IO.Read (File, Raw, Last);
      IO.Close (File);
      if Last > Max_Wire then
         raise Ada.IO_Exceptions.Data_Error with "wire limit exceeded";
      end if;
      Length := Natural (Last);
      for J in 1 .. Length loop
         Wire (J) := Byte (Raw (Stream_Element_Offset (J)));
      end loop;
   exception
      when others =>
         if IO.Is_Open (File) then
            IO.Close (File);
         end if;
         raise;
   end Read_Wire;

   procedure Read_Source
     (Path : String; Source : out Source_Buffer; Length : out Source_Length)
   is
      Wire : Wire_Buffer;
      Size : Wire_Length;
   begin
      Read_Wire (Path, Wire, Size);
      if Size > Max_Source then
         raise Ada.IO_Exceptions.Data_Error with "source limit exceeded";
      end if;
      Source := [others => 0];
      Length := Size;
      for J in 1 .. Length loop
         Source (J) := Wire (J);
      end loop;
   end Read_Source;

   procedure Write_Source
     (Source : Source_Buffer; Length : Source_Length)
   is
      Written : Integer;
   begin
      pragma Compile_Time_Error
        (Source_Buffer'Component_Size /= 8, "binary output requires byte layout");
      if Length = 0 then
         return;
      end if;
      --  Sole raw-address boundary: a live fixed array, no pointer arithmetic.
      --  Text_IO appends a final line terminator and is not a binary transport.
      Written := GNAT.OS_Lib.Write
        (GNAT.OS_Lib.Standout, Source'Address, Length);
      if Written /= Length then
         raise Ada.IO_Exceptions.Data_Error with "short binary write";
      end if;
   end Write_Source;

   procedure Run_Source_Command
     (Mode : Source_Command; Wire_Path, Source_Path : String;
      Result : out Status)
   is
      Wire : Wire_Buffer;
      Output, Source : Source_Buffer;
      Length : Wire_Length;
      Used, Size : Source_Length;
   begin
      Read_Wire (Wire_Path, Wire, Length);
      if Mode = Check_Source then
         Read_Source (Source_Path, Source, Size);
         Transport_Decoder.Check (Wire, Length, Source, Size, Output, Used, Result);
      else
         Transport_Decoder.Decode (Wire, Length, Output, Used, Result);
      end if;
      if Result /= Ok then
         return;
      end if;
      if Mode = Decode_Source then
         Write_Source (Output, Used);
      else
         Ada.Text_IO.Put_Line ("OK " & Source_Length'Image (Used));
      end if;
   end Run_Source_Command;

   procedure Observe_Path
     (Graph_Path, Choices_Path : String;
      Found : out Transport_Graphs.Node_Ref; Result : out Status)
   is
      Wire : Wire_Buffer;
      Length : Wire_Length;
      G : Transport_Graphs.Graph;
      Choices : Transport_Paths.Path;
      Count : Transport_Paths.Path_Length;
   begin
      Found := 0;
      Read_Wire (Graph_Path, Wire, Length);
      Transport_Graph_Parse.Read_Graph (Wire, Length, G, Result);
      if Result /= Ok then
         return;
      end if;
      Read_Wire (Choices_Path, Wire, Length);
      Transport_Graph_Parse.Read_Path (Wire, Length, Choices, Count, Result);
      if Result /= Ok then
         return;
      end if;
      Found := Transport_Paths.Follow (G, Choices, Count);
   end Observe_Path;

   procedure Run_Temporal (Path : String; Result : out Status) is
      Wire : Wire_Buffer;
      Length : Wire_Length;
      Item : Transport_Temporal.Model;
   begin
      Read_Wire (Path, Wire, Length);
      Transport_Temporal_Parse.Read_Model (Wire, Length, Item, Result);
      if Result = Ok then
         Ada.Text_IO.Put_Line
           ("OK MODEL " & Transport_Temporal.Outcome'Image (Transport_Temporal.Evaluate (Item)));
      end if;
   end Run_Temporal;

   procedure Check_Graphs
     (Original_Path, Candidate_Path, Map_Path : String; Result : out Status)
   is
      Wire : Wire_Buffer;
      Length : Wire_Length;
      Original, Candidate : Transport_Graphs.Graph;
      Map : Transport_Graphs.Node_Map;
   begin
      Read_Wire (Original_Path, Wire, Length);
      Transport_Graph_Parse.Read_Graph (Wire, Length, Original, Result);
      if Result /= Ok then
         return;
      end if;
      Read_Wire (Candidate_Path, Wire, Length);
      Transport_Graph_Parse.Read_Graph (Wire, Length, Candidate, Result);
      if Result /= Ok then
         return;
      end if;
      Read_Wire (Map_Path, Wire, Length);
      Transport_Graph_Parse.Read_Map (Wire, Length, Original.Count, Map, Result);
      if Result /= Ok then
         return;
      end if;
      Transport_Graphs.Check (Original, Candidate, Map, Result);
   end Check_Graphs;
end Transport_IO;

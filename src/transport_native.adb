with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;
with Transport_Graphs;
with Transport_IO;
with Transport_Types; use Transport_Types;

procedure Transport_Native with SPARK_Mode => Off is
   use Ada.Command_Line;
   Found : Transport_Graphs.Node_Ref;
   Result : Status;
begin
   if Argument_Count = 4 and then Argument (1) = "graph-check" then
      Transport_IO.Check_Graphs (Argument (2), Argument (3), Argument (4), Result);
      Ada.Text_IO.Put_Line (Status'Image (Result) & " GRAPH");
      if Result /= Ok then
         Set_Exit_Status (Failure);
      end if;
      return;
   elsif Argument_Count = 2 and then Argument (1) = "temporal" then
      Transport_IO.Run_Temporal (Argument (2), Result);
   elsif Argument_Count = 3 and then Argument (1) = "path" then
      Transport_IO.Observe_Path (Argument (2), Argument (3), Found, Result);
      if Result = Ok then
         Ada.Text_IO.Put_Line ("OK PATH" & Transport_Graphs.Node_Ref'Image (Found));
      end if;
   elsif Argument_Count < 2 or else Argument_Count > 3 or else
     not ((Argument (1) = "decode" and then Argument_Count = 2) or else
          (Argument (1) = "check" and then Argument_Count = 3))
   then
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "usage: transport_native decode WIRE | check WIRE SOURCE | " &
         "graph-check ORIGINAL CANDIDATE MAP | path GRAPH CHOICES | temporal MODEL");
      Set_Exit_Status (Failure);
      return;
   elsif Argument (1) = "check" then
      Transport_IO.Run_Source_Command
        (Transport_IO.Check_Source, Argument (2), Argument (3), Result);
   else
      Transport_IO.Run_Source_Command
        (Transport_IO.Decode_Source, Argument (2), "", Result);
   end if;
   if Result /= Ok then
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, Status'Image (Result));
      Set_Exit_Status (Failure);
   end if;
exception
   when Error : others =>
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "IO_ERROR " & Ada.Exceptions.Exception_Name (Error));
      Set_Exit_Status (Failure);
end Transport_Native;

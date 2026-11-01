with Ada.Command_Line;
with Ada.Text_IO;
with Document_Binary_IO;
with Document_Framed_Decode;

procedure Document_Native_Decode is
begin
   if Ada.Command_Line.Argument_Count /= 1 then
      raise Document_Binary_IO.Protocol_Error;
   end if;
   Document_Framed_Decode.Run_File (Ada.Command_Line.Argument (1));
exception
   when others =>
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, "FT01 input refused");
end Document_Native_Decode;

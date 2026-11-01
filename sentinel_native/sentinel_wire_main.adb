with Ada.Command_Line;
with Sentinel_Wire_IO;

procedure Sentinel_Wire_Main is
   Code : Natural;
begin
   Sentinel_Wire_IO.Run (Code);
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Exit_Status (Code));
exception
   when Constraint_Error | Program_Error | Storage_Error =>
      Ada.Command_Line.Set_Exit_Status (3);
end Sentinel_Wire_Main;

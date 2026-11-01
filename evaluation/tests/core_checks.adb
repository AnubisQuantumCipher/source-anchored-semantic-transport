with Ada.Text_IO;
with Core_Checks_Support;

procedure Core_Checks with SPARK_Mode => Off is
begin
   Core_Checks_Support.Truth_Tables;
   Core_Checks_Support.Finite_Tables;
   Core_Checks_Support.Frames;
   Ada.Text_IO.Put_Line ("PASS CORE_CHECKS");
end Core_Checks;

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;
with Transport_IO;
with Transport_Types; use Transport_Types;
with Transport_Eval; use Transport_Eval;
with Transport_Core_Parse;

--  File and output boundary is tested, not SPARK-proved. No model is acquired here.
procedure Transport_Core_Native with SPARK_Mode => Off is
   use Ada.Command_Line;
   use Ada.Text_IO;
   Wire : Wire_Buffer;
   Length : Wire_Length;
   T : Core_Tree;
   M : Finite_Model;
   V : Values;
   Result : Status;
begin
   if Argument_Count /= 1 then
      Put_Line (Standard_Error, "usage: transport_core_native STC3_FRAME");
      Set_Exit_Status (Failure);
      return;
   end if;
   Transport_IO.Read_Wire (Argument (1), Wire, Length);
   Transport_Core_Parse.Read (Wire, Length, T, M, Result);
   if Result /= Ok then
      Put_Line (Standard_Error, "REFUSED " & Status'Image (Result));
      Set_Exit_Status (Failure);
      return;
   end if;
   Evaluate (T, M, V);
   Put_Line ("OK CORE3 " & Sort'Image (Kind (T.Items (T.Count).Op)));
   for I in 1 .. T.Count loop
      Put_Line ("NODE" & Natural'Image (I) & " " & Sort'Image (Kind (T.Items (I).Op)) &
                " " & Fact_Truth'Image (V (I).Truth) & " " &
                Norm_Outcome'Image (V (I).Outcome));
   end loop;
exception
   when Error : others =>
      Put_Line (Standard_Error, "IO_ERROR " & Ada.Exceptions.Exception_Name (Error));
      Set_Exit_Status (Failure);
end Transport_Core_Native;

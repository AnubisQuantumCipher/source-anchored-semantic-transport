with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;
with Transport_Eval; use Transport_Eval;
with Transport_Bound_Eval;
with Transport_Bound_Eval_IO;
with Transport_Bound_Eval_Parse; use Transport_Bound_Eval_Parse;

--  Command-line, stream and output boundaries are tested, outside the proof.
procedure Transport_Bound_Eval_Native with SPARK_Mode => Off is
   use Ada.Command_Line;
   use Ada.Text_IO;
   Wire : Frame_Buffer;
   Length : Frame_Length;
   T : Tree;
   Observed : Transport_Bound_Eval.Observations;
   Evaluated : Values;
   Result : Parse_Status;
   Valid : Boolean;
begin
   if Argument_Count /= 1 then
      Put_Line (Standard_Error, "usage: transport_bound_eval_native STV1_FRAME");
      Set_Exit_Status (Failure);
      return;
   end if;
   Transport_Bound_Eval_IO.Read_Frame (Argument (1), Wire, Length, Valid);
   if not Valid then
      Put_Line (Standard_Error, "REFUSED IO_ERROR");
      Set_Exit_Status (Failure);
      return;
   end if;
   Read (Wire, Length, T, Observed, Result);
   if Result /= Ok then
      Put_Line (Standard_Error, "REFUSED INVALID_FRAME");
      Set_Exit_Status (Failure);
      return;
   end if;
   Transport_Bound_Eval.Evaluate (T, Observed, Evaluated);
   for I in 1 .. T.Count loop
      if Kind (T.Items (I).Op) = Fact then
         Put_Line ("NODE" & Natural'Image (I) & " FACT " &
                     Fact_Truth'Image (Evaluated (I).Truth));
      else
         Put_Line ("NODE" & Natural'Image (I) & " NORM " &
                     Norm_Outcome'Image (Evaluated (I).Outcome));
      end if;
   end loop;
exception
   when Error : others =>
      Put_Line (Standard_Error, "IO_ERROR " & Ada.Exceptions.Exception_Name (Error));
      Set_Exit_Status (Failure);
end Transport_Bound_Eval_Native;

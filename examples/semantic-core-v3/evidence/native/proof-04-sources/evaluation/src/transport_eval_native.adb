with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;
with Transport_IO;
with Transport_Types; use Transport_Types;
with Transport_Eval;
with Transport_Eval_Parse;
with Transport_Child_Harness;

--  Existing stream boundary reused; command-line/output boundary is TESTED only.
procedure Transport_Eval_Native with SPARK_Mode => Off is
   use Ada.Command_Line;
   use Ada.Text_IO;
   Wire : Wire_Buffer;
   Length : Wire_Length;
   Tree : Transport_Eval.Tree;
   Values : Transport_Eval.Values;
   Mode : Transport_Child_Harness.Scenario;
   Steps : Transport_Child_Harness.Step_Count;
   Parent, Child : Transport_Child_Harness.Scalar;
   Observation : Transport_Child_Harness.Observation;
   Result : Status;
begin
   if Argument_Count /= 1 then
      Put_Line (Standard_Error, "usage: transport_eval_native EVALUATION_FRAME");
      Set_Exit_Status (Failure);
      return;
   end if;
   Transport_IO.Read_Wire (Argument (1), Wire, Length);
   Transport_Eval_Parse.Read (Wire, Length, Tree, Mode, Steps, Parent, Child, Result);
   if Result /= Ok then
      Put_Line (Standard_Error, "REFUSED " & Status'Image (Result));
      Set_Exit_Status (Failure);
      return;
   end if;
   Transport_Child_Harness.Run (Mode, Steps, Parent, Child, Observation);
   Transport_Eval.Evaluate (Tree, Transport_Child_Harness.Fact (Observation), Values);
   Put_Line ("OK NORM " & Transport_Eval.Norm_Outcome'Image (Values (Tree.Count).Outcome));
   Put_Line ("FACT " & Transport_Eval.Fact_Truth'Image (Transport_Child_Harness.Fact (Observation)));
   Put_Line ("RUN" & Natural'Image (Observation.Completed) & Natural'Image (Observation.Attempts) &
             " " & Boolean'Image (Observation.Complete) & Natural'Image (Observation.Before_Parent) &
             Natural'Image (Observation.After_Parent) & Natural'Image (Observation.Before_Child) &
             Natural'Image (Observation.After_Child));
   for I in 1 .. Tree.Count loop
      Put_Line ("NODE" & Natural'Image (I) & " " & Transport_Eval.Fact_Truth'Image (Values (I).Truth) &
                " " & Transport_Eval.Norm_Outcome'Image (Values (I).Outcome));
   end loop;
exception
   when Error : others =>
      Put_Line (Standard_Error, "IO_ERROR " & Ada.Exceptions.Exception_Name (Error));
      Set_Exit_Status (Failure);
end Transport_Eval_Native;

with Transport_Bound_Eval_Parse; use Transport_Bound_Eval_Parse;

--  OS stream boundary: bounded and tested, outside the SPARK proof.
package Transport_Bound_Eval_IO with SPARK_Mode => Off is
   procedure Read_Frame
     (Path : String; Wire : out Frame_Buffer; Length : out Frame_Length;
      Valid : out Boolean);
end Transport_Bound_Eval_IO;

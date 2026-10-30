with Transport_Eval; use Transport_Eval;
with Transport_Bound_Eval; use Transport_Bound_Eval;

package Transport_Bound_Eval_Parse with SPARK_Mode is
   Header_Size : constant := 6;
   Record_Size : constant := 6;
   Max_Frame : constant := Header_Size + Record_Size * Max_Nodes;
   type Byte is mod 256 with Size => 8;
   subtype Frame_Length is Natural range 0 .. Max_Frame;
   type Frame_Buffer is array (Positive range 1 .. Max_Frame) of Byte;
   type Parse_Status is (Ok, Invalid_Frame);

   function Connected (T : Tree) return Boolean
   with Global => null, Pre => Well_Formed (T);

   procedure Read
     (Wire : Frame_Buffer; Length : Frame_Length; T : out Tree;
      Observed : out Observations; Result : out Parse_Status)
   with Global => null, Always_Terminates,
     Post =>
       (if Result = Ok then
          Well_Formed (T) and then Consistent (T, Observed) and then Connected (T)
        else T = Tree'(others => <>) and
          (for all I in Node_Id => Observed (I) = Unresolved));
end Transport_Bound_Eval_Parse;

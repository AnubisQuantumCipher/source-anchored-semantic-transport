with Transport_Types; use Transport_Types;

package Transport_Buffers with SPARK_Mode is
   procedure Read_Token
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      Item : out Symbol; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Pos <= Length + 1,
     Post => Pos <= Length + 1 and then Pos >= Pos'Old
       and then (if Result = Ok then
           Item.Size > 0 and then Pos = Pos'Old + Item.Size + 1
           and then (for all J in 1 .. Item.Size =>
             Item.Data (J) = Wire (Pos'Old + J))
         else Item.Size = 0);

   procedure Append
     (Item : Symbol; Output : in out Source_Buffer;
      Used : in out Source_Length; Result : out Status)
   with Global => null, Always_Terminates,
     Post =>
       (if Item.Size > Max_Source - Used'Old then
          Result = Capacity_Exceeded and then Used = Used'Old
          and then Output = Output'Old
        else Result = Ok and then Used = Used'Old + Item.Size
          and then (for all J in 1 .. Used'Old =>
            Output (J) = Output'Old (J))
          and then (for all J in 1 .. Item.Size =>
            Output (Used'Old + J) = Item.Data (J)));

   function Equal
     (Left, Right : Source_Buffer; L_Size, R_Size : Source_Length)
      return Boolean
   with Global => null,
     Post => Equal'Result =
       (L_Size = R_Size and then
        (for all J in 1 .. L_Size => Left (J) = Right (J)));
end Transport_Buffers;

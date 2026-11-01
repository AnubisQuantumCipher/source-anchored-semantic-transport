package Sentinel_Wire_IO is
   Input_Cap : constant := 1_048_576;
   Output_Size : constant := 2_725;
   Operation_Cap : constant := 2_841;
   procedure Run (Exit_Code : out Natural)
     with Post => Exit_Code in 0 | 2 | 3;
end Sentinel_Wire_IO;

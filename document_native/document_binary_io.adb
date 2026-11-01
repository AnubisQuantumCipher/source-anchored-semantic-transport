with GNAT.OS_Lib;

package body Document_Binary_IO is
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_64;

   procedure Read_Exact
     (File : Ada.Streams.Stream_IO.File_Type;
      Data : out Ada.Streams.Stream_Element_Array)
   is
      Last : Ada.Streams.Stream_Element_Offset;
   begin
      Ada.Streams.Stream_IO.Read (File, Data, Last);
      if Last /= Data'Last then
         raise Protocol_Error with "truncated FT01 input";
      end if;
   end Read_Exact;

   function Read_Unsigned
     (File : Ada.Streams.Stream_IO.File_Type; Width : Integer_Width)
      return Interfaces.Unsigned_64
   is
      Data : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Width));
      Value : Interfaces.Unsigned_64 := 0;
   begin
      Read_Exact (File, Data);
      for Item of Data loop
         Value := Value * 256 + Interfaces.Unsigned_64 (Item);
      end loop;
      return Value;
   end Read_Unsigned;

   procedure Read_Wire
     (File : Ada.Streams.Stream_IO.File_Type;
      Length : Transport_Types.Wire_Length;
      Wire : out Transport_Types.Wire_Buffer)
   is
      Data : Ada.Streams.Stream_Element_Array
        (1 .. Transport_Types.Max_Wire);
   begin
      Wire := [others => 0];
      Read_Exact (File, Data (1 .. Ada.Streams.Stream_Element_Offset (Length)));
      for J in 1 .. Length loop
         Wire (J) := Transport_Types.Byte
           (Data (Ada.Streams.Stream_Element_Offset (J)));
      end loop;
   end Read_Wire;

   procedure Write_Source
     (Data : Transport_Types.Source_Buffer;
      Length : Transport_Types.Source_Length)
   is
      Done : Natural := 0;
      Written : Integer;
   begin
      for Attempt in 1 .. Transport_Types.Max_Source loop
         exit when Done = Length;
         Written := GNAT.OS_Lib.Write
           (GNAT.OS_Lib.Standout, Data (Done + 1)'Address, Length - Done);
         if Written <= 0 or else Written > Length - Done then
            raise Protocol_Error with "stdout write failed";
         end if;
         Done := Done + Written;
      end loop;
      if Done /= Length then
         raise Protocol_Error with "stdout incomplete";
      end if;
   end Write_Source;
end Document_Binary_IO;

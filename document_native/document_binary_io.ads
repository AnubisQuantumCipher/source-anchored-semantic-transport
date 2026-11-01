with Ada.Streams;
with Ada.Streams.Stream_IO;
with Interfaces;
with Transport_Types;

package Document_Binary_IO is
   Protocol_Error : exception;
   subtype Integer_Width is Positive range 1 .. 8;
   procedure Read_Exact
     (File : Ada.Streams.Stream_IO.File_Type;
      Data : out Ada.Streams.Stream_Element_Array);
   function Read_Unsigned
     (File : Ada.Streams.Stream_IO.File_Type; Width : Integer_Width)
      return Interfaces.Unsigned_64;
   procedure Read_Wire
     (File : Ada.Streams.Stream_IO.File_Type;
      Length : Transport_Types.Wire_Length;
      Wire : out Transport_Types.Wire_Buffer);
   procedure Write_Source
     (Data : Transport_Types.Source_Buffer;
      Length : Transport_Types.Source_Length);
end Document_Binary_IO;

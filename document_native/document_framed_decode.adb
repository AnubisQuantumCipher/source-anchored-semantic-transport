with Ada.Streams;
with Ada.Streams.Stream_IO;
with Document_Binary_IO;
with Document_Frame_Ledger;
with Interfaces;
with Transport_Decoder;
with Transport_Types;

package body Document_Framed_Decode is
   use type Ada.Streams.Stream_Element_Array;
   use type Interfaces.Unsigned_64;
   use type Transport_Types.Status;
   package Binary renames Document_Binary_IO;
   package Ledger renames Document_Frame_Ledger;
   package Files renames Ada.Streams.Stream_IO;

   procedure Header
     (Input : Files.File_Type; State : out Ledger.Ledger)
   is
      Magic : Ada.Streams.Stream_Element_Array (1 .. 4);
      Total, Count : Interfaces.Unsigned_64;
   begin
      Binary.Read_Exact (Input, Magic);
      if Magic /= [70, 84, 48, 49] then
         raise Binary.Protocol_Error;
      end if;
      Total := Binary.Read_Unsigned (Input, 8);
      Count := Binary.Read_Unsigned (Input, 4);
      if Total > Ledger.Max_Source or else Count > Ledger.Max_Frames then
         raise Binary.Protocol_Error;
      end if;
      Ledger.Initialize
        (State, Ledger.Source_Size (Total), Ledger.Frame_Count (Count));
      if State.Rejected then
         raise Binary.Protocol_Error;
      end if;
   end Header;

   procedure Frame
     (Input : Files.File_Type; State : in out Ledger.Ledger)
   is
      Ordinal, Offset, Size, Wire_Size : Interfaces.Unsigned_64;
      Wire : Transport_Types.Wire_Buffer;
      Output : Transport_Types.Source_Buffer;
      Used : Transport_Types.Source_Length;
      Result : Transport_Types.Status;
   begin
      Ordinal := Binary.Read_Unsigned (Input, 4);
      Offset := Binary.Read_Unsigned (Input, 8);
      Size := Binary.Read_Unsigned (Input, 4);
      Wire_Size := Binary.Read_Unsigned (Input, 4);
      if Ordinal > Ledger.Max_Frames or else Offset > Ledger.Max_Source
        or else Size > Ledger.Frame_Size or else Wire_Size = 0
        or else Wire_Size > Transport_Types.Max_Wire
      then
         raise Binary.Protocol_Error;
      end if;
      Ledger.Accept_Frame
        (State, Ledger.Frame_Count (Ordinal), Ledger.Source_Size (Offset),
         Ledger.Frame_Length (Size));
      if State.Rejected then
         raise Binary.Protocol_Error;
      end if;
      Binary.Read_Wire (Input, Transport_Types.Wire_Length (Wire_Size), Wire);
      Transport_Decoder.Decode
        (Wire, Transport_Types.Wire_Length (Wire_Size), Output, Used, Result);
      if Result /= Transport_Types.Ok or else Used /= Natural (Size) then
         raise Binary.Protocol_Error;
      end if;
      Binary.Write_Source (Output, Used);
   end Frame;

   procedure Run_File (Name : String) is
      Input : Files.File_Type;
      State : Ledger.Ledger;
   begin
      Files.Open (Input, Files.In_File, Name);
      Header (Input, State);
      for Ordinal in 1 .. State.Count loop
         Frame (Input, State);
      end loop;
      if not Ledger.Complete (State) or else not Files.End_Of_File (Input) then
         raise Binary.Protocol_Error;
      end if;
      Files.Close (Input);
   exception
      when others =>
         -- Cleanup failure keeps the same refusal verdict; never grants success.
         begin
            if Files.Is_Open (Input) then
               Files.Close (Input);
            end if;
         exception
            when others =>
               raise Binary.Protocol_Error with "FT01 close failed";
         end;
         raise Binary.Protocol_Error with "FT01 decode failed";
   end Run_File;
end Document_Framed_Decode;

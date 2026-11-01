with Transport_Buffers;

package body Transport_Decoder with SPARK_Mode is
   procedure Symbol_Op
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      Define : Boolean; Table : in out Symbol_Table;
      Output : in out Source_Buffer; Used : in out Source_Length;
      Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Pos <= Length + 1, Post => Pos <= Length + 1 and then Pos >= Pos'Old
   is
      Id   : Symbol_Id;
      Item : Symbol;
   begin
      Result := Truncated;
      if Pos > Length then
         return;
      end if;
      if Natural (Wire (Pos)) >= Max_Symbol then
         Result := Invalid_Symbol;
         return;
      end if;
      Id := Natural (Wire (Pos));
      Pos := Pos + 1;
      if Define then
         if Table (Id).Size /= 0 then
            Result := Duplicate_Symbol;
            return;
         end if;
         Transport_Buffers.Read_Token (Wire, Length, Pos, Item, Result);
         if Result = Ok then
            Table (Id) := Item;
         end if;
      else
         if Table (Id).Size = 0 then
            Result := Invalid_Symbol;
            return;
         end if;
         Transport_Buffers.Append (Table (Id), Output, Used, Result);
      end if;
   end Symbol_Op;

   procedure Step
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      Table : in out Symbol_Table; Output : in out Source_Buffer;
      Used : in out Source_Length; Done : out Boolean; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Pos <= Length, Post => Pos <= Length + 1 and then Pos > Pos'Old
   is
      Op   : constant Byte := Wire (Pos);
      Item : Symbol;
   begin
      Pos := Pos + 1;
      Done := False;
      Result := Ok;
      case Op is
         when 0 =>
            Transport_Buffers.Read_Token (Wire, Length, Pos, Item, Result);
            if Result = Ok then
               Transport_Buffers.Append (Item, Output, Used, Result);
            end if;
         when 1 | 2 =>
            Symbol_Op
              (Wire, Length, Pos, Op = 1, Table, Output, Used, Result);
         when 255 =>
            Done := True;
            if Pos /= Length + 1 then
               Result := Trailing_Data;
            end if;
         when others =>
            Result := Invalid_Opcode;
      end case;
   end Step;

   procedure Expand
     (Wire : Wire_Buffer; Length : Wire_Length; Output : out Source_Buffer;
      Used : out Source_Length; Result : out Status)
   with Global => null, Always_Terminates
   is
      Table : Symbol_Table := [others => (Data => [others => 0], Size => 0)];
      Pos   : Cursor := 5;
      Done  : Boolean;
   begin
      Used := 0;
      Output := [others => 0];
      Result := Bad_Header;
      if Length < 4 or else Wire (1 .. 4) /= [83, 84, 66, 49] then
         return;
      end if;
      for Iteration in 1 .. Max_Wire loop
         pragma Loop_Invariant (Pos <= Length + 1);
         if Pos > Length then
            Result := Missing_End;
            return;
         end if;
         Step (Wire, Length, Pos, Table, Output, Used, Done, Result);
         if Result /= Ok or else Done then
            return;
         end if;
      end loop;
      Result := Missing_End;
   end Expand;

   procedure Decode
     (Wire : Wire_Buffer; Length : Wire_Length; Output : out Source_Buffer;
      Used : out Source_Length; Result : out Status)
   is
   begin
      Expand (Wire, Length, Output, Used, Result);
      if Result /= Ok then
         Used := 0;
         Output := [others => 0];
      end if;
   end Decode;

   procedure Check
     (Wire : Wire_Buffer; Length : Wire_Length; Source : Source_Buffer;
      Size : Source_Length; Output : out Source_Buffer;
      Used : out Source_Length; Result : out Status)
   is
   begin
      Decode (Wire, Length, Output, Used, Result);
      if Result = Ok and then not Transport_Buffers.Equal (Output, Source, Used, Size)
      then
         Result := Source_Mismatch;
         Used := 0;
         Output := [others => 0];
      end if;
   end Check;
end Transport_Decoder;

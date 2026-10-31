package body Transport_Buffers with SPARK_Mode is
   procedure Read_Token
     (Wire : Wire_Buffer; Length : Wire_Length; Pos : in out Cursor;
      Item : out Symbol; Result : out Status)
   is
      Start : constant Cursor := Pos;
      Size  : Token_Length;
   begin
      Item := (Data => [others => 0], Size => 0);
      Result := Truncated;
      if Pos > Length then
         return;
      end if;
      Size := Natural (Wire (Pos));
      if Size = 0 then
         Result := Empty_Token;
         return;
      end if;
      if Size > Length - Pos then
         return;
      end if;
      for J in 1 .. Size loop
         Item.Data (J) := Wire (Start + J);
         pragma Loop_Invariant
           (for all K in 1 .. J => Item.Data (K) = Wire (Start + K));
      end loop;
      Item.Size := Size;
      Pos := Start + Size + 1;
      Result := Ok;
   end Read_Token;

   procedure Append
     (Item : Symbol; Output : in out Source_Buffer;
      Used : in out Source_Length; Result : out Status)
   is
      Start : constant Source_Length := Used;
   begin
      if Item.Size > Max_Source - Used then
         Result := Capacity_Exceeded;
         return;
      end if;
      for J in 1 .. Item.Size loop
         Output (Start + J) := Item.Data (J);
         pragma Loop_Invariant
           (for all K in 1 .. J => Output (Start + K) = Item.Data (K));
         pragma Loop_Invariant
           (for all K in 1 .. Start => Output (K) = Output'Loop_Entry (K));
      end loop;
      Used := Start + Item.Size;
      Result := Ok;
   end Append;

   function Equal
     (Left, Right : Source_Buffer; L_Size, R_Size : Source_Length)
      return Boolean
   is
   begin
      if L_Size /= R_Size then
         return False;
      end if;
      for J in 1 .. L_Size loop
         if Left (J) /= Right (J) then
            return False;
         end if;
         pragma Loop_Invariant
           (for all K in 1 .. J => Left (K) = Right (K));
      end loop;
      return True;
   end Equal;
end Transport_Buffers;

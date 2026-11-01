package Transport_Types with SPARK_Mode, Pure is
   Max_Wire   : constant := 131_072;
   Max_Source : constant := 65_536;
   Max_Token  : constant := 255;
   Max_Symbol : constant := 64;
   type Byte is mod 256 with Size => 8;
   subtype Wire_Length is Natural range 0 .. Max_Wire;
   subtype Source_Length is Natural range 0 .. Max_Source;
   subtype Cursor is Positive range 1 .. Max_Wire + 1;
   subtype Token_Length is Natural range 0 .. Max_Token;
   subtype Symbol_Id is Natural range 0 .. Max_Symbol - 1;
   type Wire_Buffer is array (Positive range 1 .. Max_Wire) of Byte;
   type Source_Buffer is array (Positive range 1 .. Max_Source) of Byte;
   type Token_Buffer is array (Positive range 1 .. Max_Token) of Byte;
   type Symbol is record
      Data : Token_Buffer := [others => 0];
      Size : Token_Length := 0;
   end record;
   type Symbol_Table is array (Symbol_Id) of Symbol;
   type Status is
     (Ok, Bad_Header, Truncated, Invalid_Opcode, Invalid_Symbol,
      Duplicate_Symbol, Empty_Token, Capacity_Exceeded, Missing_End,
      Trailing_Data, Source_Mismatch, Invalid_Graph, Graph_Mismatch,
      Invalid_Model);
end Transport_Types;

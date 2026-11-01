package Document_Frame_Ledger with SPARK_Mode, Pure is
   Max_Source : constant := 1_073_741_824;
   Frame_Size : constant := 65_536;
   Max_Frames : constant := 16_384;
   subtype Source_Size is Natural range 0 .. Max_Source;
   subtype Frame_Count is Natural range 0 .. Max_Frames;
   subtype Frame_Length is Natural range 0 .. Frame_Size;

   function Required_Frames (Total : Source_Size) return Frame_Count is
     (if Total = 0 then 0 else (Total - 1) / Frame_Size + 1);

   type Ledger is record
      Total    : Source_Size := 0;
      Count    : Frame_Count := 0;
      Accepted : Frame_Count := 0;
      Bytes    : Source_Size := 0;
      Rejected : Boolean := False;
   end record;

   function Valid (Item : Ledger) return Boolean is
     (Item.Count = Required_Frames (Item.Total)
      and then Item.Accepted <= Item.Count and then Item.Bytes <= Item.Total
      and then
        (if Item.Accepted = Item.Count then Item.Bytes = Item.Total
         else Item.Bytes = Item.Accepted * Frame_Size));

   function Complete (Item : Ledger) return Boolean is
     (Valid (Item) and then not Item.Rejected
      and then Item.Accepted = Item.Count and then Item.Bytes = Item.Total);

   function Next_Length (Item : Ledger) return Frame_Length is
     (if Item.Bytes > Item.Total then 0
      elsif Item.Total - Item.Bytes >= Frame_Size then Frame_Size
      else Item.Total - Item.Bytes);

   function Admissible
     (Item : Ledger; Ordinal : Frame_Count; Offset : Source_Size;
      Size : Frame_Length) return Boolean is
     (Valid (Item) and then not Item.Rejected
      and then Item.Accepted < Item.Count and then Ordinal = Item.Accepted
      and then Offset = Item.Bytes and then Size > 0
      and then Size = Next_Length (Item));

   procedure Initialize
     (Item : out Ledger; Total : Source_Size; Declared : Frame_Count)
   with Global => null, Always_Terminates,
     Post => Valid (Item) and then Item.Total = Total
       and then Item.Count = Required_Frames (Total)
       and then Item.Accepted = 0 and then Item.Bytes = 0
       and then Item.Rejected = (Declared /= Required_Frames (Total));

   procedure Accept_Frame
     (Item : in out Ledger; Ordinal : Frame_Count; Offset : Source_Size;
      Size : Frame_Length)
   with Global => null, Always_Terminates, Pre => Valid (Item),
     Post => Valid (Item) and then Item.Total = Item.Total'Old
       and then Item.Count = Item.Count'Old
       and then
         (if Admissible (Item'Old, Ordinal, Offset, Size) then
            not Item.Rejected and then Item.Accepted = Item.Accepted'Old + 1
            and then Item.Bytes = Item.Bytes'Old + Size
          else Item.Rejected and then Item.Accepted = Item.Accepted'Old
            and then Item.Bytes = Item.Bytes'Old);
end Document_Frame_Ledger;

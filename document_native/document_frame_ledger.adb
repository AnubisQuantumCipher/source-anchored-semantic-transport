package body Document_Frame_Ledger with SPARK_Mode is
   procedure Initialize
     (Item : out Ledger; Total : Source_Size; Declared : Frame_Count)
   is
   begin
      Item := (Total => Total, Count => Required_Frames (Total),
               Accepted => 0, Bytes => 0,
               Rejected => Declared /= Required_Frames (Total));
   end Initialize;

   procedure Accept_Frame
     (Item : in out Ledger; Ordinal : Frame_Count; Offset : Source_Size;
      Size : Frame_Length)
   is
   begin
      if not Admissible (Item, Ordinal, Offset, Size) then
         Item.Rejected := True;
         return;
      end if;
      Item.Bytes := Item.Bytes + Size;
      Item.Accepted := Item.Accepted + 1;
   end Accept_Frame;
end Document_Frame_Ledger;

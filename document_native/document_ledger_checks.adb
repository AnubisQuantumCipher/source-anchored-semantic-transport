with Document_Frame_Ledger; use Document_Frame_Ledger;

procedure Document_Ledger_Checks is
   procedure Sequence (Total : Source_Size) is
      Item : Ledger;
   begin
      Initialize (Item, Total, Required_Frames (Total));
      pragma Assert (not Item.Rejected and then Valid (Item));
      for J in 1 .. Item.Count loop
         pragma Assert (not Complete (Item));
         Accept_Frame (Item, Item.Accepted, Item.Bytes, Next_Length (Item));
         pragma Assert (not Item.Rejected and then Valid (Item));
      end loop;
      pragma Assert (Complete (Item));
      Accept_Frame (Item, Item.Accepted, Item.Bytes, 1);
      pragma Assert (Item.Rejected and then not Complete (Item));
   end Sequence;

   procedure Refusal
     (Ordinal : Frame_Count; Offset : Source_Size; Size : Frame_Length)
   is
      Item : Ledger;
   begin
      Initialize (Item, Frame_Size + 1, 2);
      Accept_Frame (Item, Ordinal, Offset, Size);
      pragma Assert (Item.Rejected and then Item.Bytes = 0
                     and then Item.Accepted = 0 and then not Complete (Item));
      Accept_Frame (Item, 0, 0, Frame_Size);
      pragma Assert (Item.Rejected and then Item.Bytes = 0
                     and then Item.Accepted = 0 and then Valid (Item));
   end Refusal;

   procedure Final_Size is
      Item : Ledger;
   begin
      Initialize (Item, Frame_Size + 1, 2);
      Accept_Frame (Item, 0, 0, Frame_Size);
      Accept_Frame (Item, 1, Frame_Size, 2);
      pragma Assert (Item.Rejected and then Item.Bytes = Frame_Size
                     and then Item.Accepted = 1 and then not Complete (Item));
      Accept_Frame (Item, 1, Frame_Size, 1);
      pragma Assert (Item.Rejected and then Item.Bytes = Frame_Size);
   end Final_Size;
   Item : Ledger;
begin
   Sequence (0);
   Sequence (1);
   Sequence (Frame_Size - 1);
   Sequence (Frame_Size);
   Sequence (Frame_Size + 1);
   Sequence (Max_Source);
   Initialize (Item, 0, 1);
   pragma Assert (Item.Rejected and then not Complete (Item));
   Initialize (Item, 1, 0);
   pragma Assert (Item.Rejected and then not Complete (Item));
   Refusal (0, 0, 0);
   Refusal (0, 0, Frame_Size - 1);
   Refusal (1, 0, Frame_Size);
   Refusal (Max_Frames, 0, Frame_Size);
   Refusal (0, 1, Frame_Size);
   Refusal (0, Max_Source, Frame_Size);
   Final_Size;
end Document_Ledger_Checks;

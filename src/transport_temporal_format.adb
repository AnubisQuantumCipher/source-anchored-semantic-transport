package body Transport_Temporal_Format with SPARK_Mode is
   function Value (Wire : Wire_Buffer; Index : Field_Index) return Tick is
   begin
      return Tick (Wire (4 * Index + 1)) * 16_777_216 +
        Tick (Wire (4 * Index + 2)) * 65_536 +
        Tick (Wire (4 * Index + 3)) * 256 + Tick (Wire (4 * Index + 4));
   end Value;

   function Projection (Wire : Wire_Buffer; Count : Field_Count) return Fields is
      Result : Fields := [others => 0];
   begin
      for I in 1 .. Count loop
         Result (I) := Value (Wire, I);
         pragma Loop_Invariant
           (for all J in 1 .. I => Result (J) = Value (Wire, J));
         pragma Loop_Invariant (for all J in I + 1 .. Max_Fields => Result (J) = 0);
      end loop;
      return Result;
   end Projection;

   function Shape (Wire : Wire_Buffer; Length : Wire_Length) return Boolean is
   begin
      return Length >= 4 and then Wire (1) = Character'Pos ('S') and then
        Wire (2) = Character'Pos ('T') and then Wire (3) = Character'Pos ('T') and then
        Wire (4) = Character'Pos ('1') and then (Length - 4) mod 4 = 0 and then
        (Length - 4) / 4 in Fixed_Fields .. Max_Fields;
   end Shape;

   function Scope_Valid (Values : Fields; Offset : Natural) return Boolean is
   begin
      return (for all I in 1 .. 9 => Values (Offset + I) <= Tick (Reference'Last));
   end Scope_Valid;

   function Base_Valid (Values : Fields) return Boolean is
   begin
      return Scope_Valid (Values, 0) and
        Values (10) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (11) <= Modality'Pos (Modality'Last) and
        Values (15) <= Inclusion'Pos (Closed) and Values (16) <= Inclusion'Pos (Closed) and
        Values (17) <= Tick (Reference'Last) and Values (18) <= Truth'Pos (Known_True) and
        Values (19) <= Tick (Reference'Last) and Values (20) <= Max_Events;
   end Base_Valid;

   function Coverage_Valid (Values : Fields) return Boolean is
   begin
      return Scope_Valid (Values, 20) and Values (30) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (33) <= Inclusion'Pos (Closed) and Values (34) <= Inclusion'Pos (Closed) and
        Values (35) <= Tick (Reference'Last);
   end Coverage_Valid;

   function Event_Valid (Values : Fields; Offset : Natural) return Boolean is
   begin
      return Scope_Valid (Values, Offset + 1) and
        Values (Offset + 1) <= Tick (Reference'Last) and
        Values (Offset + 11) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (Offset + 13) <= Tick (Reference'Last);
   end Event_Valid;

   function Fields_Valid (Values : Fields; Count : Field_Count) return Boolean is
   begin
      return Count >= Fixed_Fields and then Base_Valid (Values) and then
        Count = Fixed_Fields + Natural (Values (20)) * Event_Fields and then
        Coverage_Valid (Values) and then
        (for all I in 1 .. Natural (Values (20)) =>
           Event_Valid (Values, Fixed_Fields + (I - 1) * Event_Fields));
   end Fields_Valid;

   function Scope_Matches
     (Values : Fields; Offset : Natural; Keys : Scope) return Boolean
   is
   begin
      return Tick (Keys.Source) = Values (Offset + 1) and
        Tick (Keys.Rule) = Values (Offset + 2) and
        Tick (Keys.Instance) = Values (Offset + 3) and
        Tick (Keys.Trigger) = Values (Offset + 4) and
        Tick (Keys.Actor) = Values (Offset + 5) and
        Tick (Keys.Subject) = Values (Offset + 6) and
        Tick (Keys.Action) = Values (Offset + 7) and
        Tick (Keys.Clock) = Values (Offset + 8) and
        Tick (Keys.Binding) = Values (Offset + 9);
   end Scope_Matches;

   function Base_Matches (Values : Fields; Item : Model) return Boolean is
   begin
      return Scope_Matches (Values, 0, Item.Keys) and
        Tick (Time_Unit'Pos (Item.Unit)) = Values (10) and
        Tick (Modality'Pos (Item.Mode)) = Values (11) and
        Item.First = Values (12) and Item.Last = Values (13) and Item.Now = Values (14) and
        Tick (Inclusion'Pos (Item.Lower)) = Values (15) and
        Tick (Inclusion'Pos (Item.Upper)) = Values (16) and
        Tick (Item.Trigger_Evidence) = Values (17) and
        Tick (Truth'Pos (Item.Exception_State)) = Values (18) and
        Tick (Item.Exception_Evidence) = Values (19) and Tick (Item.Count) = Values (20);
   end Base_Matches;

   function Coverage_Matches (Values : Fields; Observed : Coverage) return Boolean is
   begin
      return Scope_Matches (Values, 20, Observed.Keys) and
        Tick (Time_Unit'Pos (Observed.Unit)) = Values (30) and
        Observed.First = Values (31) and Observed.Last = Values (32) and
        Tick (Inclusion'Pos (Observed.Lower)) = Values (33) and
        Tick (Inclusion'Pos (Observed.Upper)) = Values (34) and
        Tick (Observed.Evidence) = Values (35);
   end Coverage_Matches;

   function Event_Matches
     (Values : Fields; Offset : Natural; Event : Observation) return Boolean
   is
   begin
      return Tick (Event.Id) = Values (Offset + 1) and
        Scope_Matches (Values, Offset + 1, Event.Keys) and
        Tick (Time_Unit'Pos (Event.Unit)) = Values (Offset + 11) and
        Event.At_Time = Values (Offset + 12) and
        Tick (Event.Evidence) = Values (Offset + 13);
   end Event_Matches;

   function Fields_Match (Values : Fields; Item : Model) return Boolean is
   begin
      return Base_Matches (Values, Item) and Coverage_Matches (Values, Item.Observed) and
        (for all I in 1 .. Item.Count =>
           Event_Matches (Values, Fixed_Fields + (I - 1) * Event_Fields, Item.History (I))) and
        (for all I in Item.Count + 1 .. Max_Events =>
           Item.History (I) = Observation'(others => <>));
   end Fields_Match;

   function Frame_Valid (Wire : Wire_Buffer; Length : Wire_Length) return Boolean is
   begin
      return Shape (Wire, Length) and then
        Fields_Valid (Projection (Wire, (Length - 4) / 4), (Length - 4) / 4);
   end Frame_Valid;

   function Represents
     (Wire : Wire_Buffer; Length : Wire_Length; Item : Model) return Boolean
   is
   begin
      return Shape (Wire, Length) and then
        Length = 4 + (Fixed_Fields + Item.Count * Event_Fields) * 4 and then
        Fields_Match (Projection (Wire, (Length - 4) / 4), Item);
   end Represents;

   procedure Prove_Frame_Validity
     (Wire : Wire_Buffer; Length : Wire_Length; Values : Fields; Count : Field_Count)
   is
      Projected : constant Fields := Projection (Wire, (Length - 4) / 4);
   begin
      pragma Assert (Count = (Length - 4) / 4);
      pragma Assert (Values = Projected);
      pragma Assert (Scope_Valid (Projected, 0) = Scope_Valid (Values, 0));
      pragma Assert (Base_Valid (Projected) = Base_Valid (Values));
      pragma Assert (Scope_Valid (Projected, 20) = Scope_Valid (Values, 20));
      pragma Assert (Coverage_Valid (Projected) = Coverage_Valid (Values));
      for I in 1 .. Max_Events loop
         pragma Assert
           (Event_Valid (Projected, Fixed_Fields + (I - 1) * Event_Fields) =
            Event_Valid (Values, Fixed_Fields + (I - 1) * Event_Fields));
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              Event_Valid (Projected, Fixed_Fields + (J - 1) * Event_Fields) =
              Event_Valid (Values, Fixed_Fields + (J - 1) * Event_Fields));
      end loop;
      pragma Assert (Fields_Valid (Projected, Count) = Fields_Valid (Values, Count));
   end Prove_Frame_Validity;
end Transport_Temporal_Format;

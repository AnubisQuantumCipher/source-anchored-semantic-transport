with Transport_Temporal; use Transport_Temporal;
with Transport_Types; use Transport_Types;

package Transport_Temporal_Format with SPARK_Mode is
   Fixed_Fields : constant := 35;
   Event_Fields : constant := 13;
   Max_Fields : constant := Fixed_Fields + Max_Events * Event_Fields;
   subtype Field_Count is Natural range 0 .. Max_Fields;
   subtype Field_Index is Positive range 1 .. Max_Fields;
   type Fields is array (Field_Index) of Tick;

   function Value (Wire : Wire_Buffer; Index : Field_Index) return Tick
   with Ghost, Global => null,
     Post => Value'Result =
       Tick (Wire (4 * Index + 1)) * 16_777_216 +
       Tick (Wire (4 * Index + 2)) * 65_536 +
       Tick (Wire (4 * Index + 3)) * 256 + Tick (Wire (4 * Index + 4));

   function Projection (Wire : Wire_Buffer; Count : Field_Count) return Fields
   with Ghost, Global => null,
     Post => (for all I in Field_Index =>
       Projection'Result (I) = (if I <= Count then Value (Wire, I) else 0));

   function Shape (Wire : Wire_Buffer; Length : Wire_Length) return Boolean
   with Ghost, Global => null,
     Post => Shape'Result =
       (Length >= 4 and then Wire (1) = Character'Pos ('S') and then
        Wire (2) = Character'Pos ('T') and then Wire (3) = Character'Pos ('T') and then
        Wire (4) = Character'Pos ('1') and then (Length - 4) mod 4 = 0 and then
        (Length - 4) / 4 in Fixed_Fields .. Max_Fields);

   function Scope_Valid (Values : Fields; Offset : Natural) return Boolean
   with Ghost, Global => null, Pre => Offset <= Max_Fields - 9,
     Post => Scope_Valid'Result =
       (for all I in 1 .. 9 => Values (Offset + I) <= Tick (Reference'Last));

   function Base_Valid (Values : Fields) return Boolean
   with Ghost, Global => null,
     Post => Base_Valid'Result =
       (Scope_Valid (Values, 0) and
        Values (10) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (11) <= Modality'Pos (Modality'Last) and
        Values (15) <= Inclusion'Pos (Closed) and Values (16) <= Inclusion'Pos (Closed) and
        Values (17) <= Tick (Reference'Last) and Values (18) <= Truth'Pos (Known_True) and
        Values (19) <= Tick (Reference'Last) and Values (20) <= Max_Events);

   function Coverage_Valid (Values : Fields) return Boolean
   with Ghost, Global => null,
     Post => Coverage_Valid'Result =
       (Scope_Valid (Values, 20) and Values (30) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (33) <= Inclusion'Pos (Closed) and Values (34) <= Inclusion'Pos (Closed) and
        Values (35) <= Tick (Reference'Last));

   function Event_Valid (Values : Fields; Offset : Natural) return Boolean
   with Ghost, Global => null, Pre => Offset <= Max_Fields - Event_Fields,
     Post => Event_Valid'Result =
       (Scope_Valid (Values, Offset + 1) and
        Values (Offset + 1) <= Tick (Reference'Last) and
        Values (Offset + 11) <= Time_Unit'Pos (Time_Unit'Last) and
        Values (Offset + 13) <= Tick (Reference'Last));

   function Fields_Valid (Values : Fields; Count : Field_Count) return Boolean
   with Ghost, Global => null,
     Post => Fields_Valid'Result =
       (Count >= Fixed_Fields and then Base_Valid (Values) and then
        Count = Fixed_Fields + Natural (Values (20)) * Event_Fields and then
        Coverage_Valid (Values) and then
        (for all I in 1 .. Natural (Values (20)) =>
           Event_Valid (Values, Fixed_Fields + (I - 1) * Event_Fields)));

   function Scope_Matches
     (Values : Fields; Offset : Natural; Keys : Scope) return Boolean
   with Ghost, Global => null, Pre => Offset <= Max_Fields - 9,
     Post => Scope_Matches'Result =
       (Tick (Keys.Source) = Values (Offset + 1) and
        Tick (Keys.Rule) = Values (Offset + 2) and
        Tick (Keys.Instance) = Values (Offset + 3) and
        Tick (Keys.Trigger) = Values (Offset + 4) and
        Tick (Keys.Actor) = Values (Offset + 5) and
        Tick (Keys.Subject) = Values (Offset + 6) and
        Tick (Keys.Action) = Values (Offset + 7) and
        Tick (Keys.Clock) = Values (Offset + 8) and
        Tick (Keys.Binding) = Values (Offset + 9));

   function Base_Matches (Values : Fields; Item : Model) return Boolean
   with Ghost, Global => null,
     Post => Base_Matches'Result =
       (Scope_Matches (Values, 0, Item.Keys) and
        Tick (Time_Unit'Pos (Item.Unit)) = Values (10) and
        Tick (Modality'Pos (Item.Mode)) = Values (11) and
        Item.First = Values (12) and Item.Last = Values (13) and Item.Now = Values (14) and
        Tick (Inclusion'Pos (Item.Lower)) = Values (15) and
        Tick (Inclusion'Pos (Item.Upper)) = Values (16) and
        Tick (Item.Trigger_Evidence) = Values (17) and
        Tick (Truth'Pos (Item.Exception_State)) = Values (18) and
        Tick (Item.Exception_Evidence) = Values (19) and Tick (Item.Count) = Values (20));

   function Coverage_Matches (Values : Fields; Observed : Coverage) return Boolean
   with Ghost, Global => null,
     Post => Coverage_Matches'Result =
       (Scope_Matches (Values, 20, Observed.Keys) and
        Tick (Time_Unit'Pos (Observed.Unit)) = Values (30) and
        Observed.First = Values (31) and Observed.Last = Values (32) and
        Tick (Inclusion'Pos (Observed.Lower)) = Values (33) and
        Tick (Inclusion'Pos (Observed.Upper)) = Values (34) and
        Tick (Observed.Evidence) = Values (35));

   function Event_Matches
     (Values : Fields; Offset : Natural; Event : Observation) return Boolean
   with Ghost, Global => null, Pre => Offset <= Max_Fields - Event_Fields,
     Post => Event_Matches'Result =
       (Tick (Event.Id) = Values (Offset + 1) and
        Scope_Matches (Values, Offset + 1, Event.Keys) and
        Tick (Time_Unit'Pos (Event.Unit)) = Values (Offset + 11) and
        Event.At_Time = Values (Offset + 12) and
        Tick (Event.Evidence) = Values (Offset + 13));

   function Fields_Match (Values : Fields; Item : Model) return Boolean
   with Ghost, Global => null,
     Post => Fields_Match'Result =
       (Base_Matches (Values, Item) and Coverage_Matches (Values, Item.Observed) and
        (for all I in 1 .. Item.Count =>
           Event_Matches (Values, Fixed_Fields + (I - 1) * Event_Fields, Item.History (I))) and
        (for all I in Item.Count + 1 .. Max_Events =>
           Item.History (I) = Observation'(others => <>)));

   function Frame_Valid (Wire : Wire_Buffer; Length : Wire_Length) return Boolean
   with Ghost, Global => null,
     Post => Frame_Valid'Result =
       (Shape (Wire, Length) and then
        Fields_Valid (Projection (Wire, (Length - 4) / 4), (Length - 4) / 4));

   function Represents
     (Wire : Wire_Buffer; Length : Wire_Length; Item : Model) return Boolean
   with Ghost, Global => null,
     Post => Represents'Result =
       (Shape (Wire, Length) and then
        Length = 4 + (Fixed_Fields + Item.Count * Event_Fields) * 4 and then
        Fields_Match (Projection (Wire, (Length - 4) / 4), Item));

   procedure Prove_Frame_Validity
     (Wire : Wire_Buffer; Length : Wire_Length; Values : Fields; Count : Field_Count)
   with Ghost, Global => null, Always_Terminates,
     Pre => Shape (Wire, Length) and then Length = 4 + Count * 4 and then
       Values = Projection (Wire, Count),
     Post => Frame_Valid (Wire, Length) = Fields_Valid (Values, Count);
end Transport_Temporal_Format;

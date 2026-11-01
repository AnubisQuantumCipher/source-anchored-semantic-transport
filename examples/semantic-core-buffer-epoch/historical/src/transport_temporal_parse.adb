with Transport_Temporal_Format; use Transport_Temporal_Format;

package body Transport_Temporal_Parse with SPARK_Mode is

   function Word (Wire : Wire_Buffer; Pos : Positive) return Tick
   with Global => null,
     Pre => Pos <= Max_Wire - 3,
     Post => Word'Result =
       Tick (Wire (Pos)) * 16_777_216 + Tick (Wire (Pos + 1)) * 65_536 +
       Tick (Wire (Pos + 2)) * 256 + Tick (Wire (Pos + 3))
   is
   begin
      return Tick (Wire (Pos)) * 16_777_216 +
        Tick (Wire (Pos + 1)) * 65_536 +
        Tick (Wire (Pos + 2)) * 256 + Tick (Wire (Pos + 3));
   end Word;

   procedure Read_Fields
     (Wire : Wire_Buffer; Length : Wire_Length;
      Values : out Fields; Count : out Field_Count; Result : out Status)
   with Global => null, Always_Terminates,
     Post => ((Result = Ok) = Shape (Wire, Length)) and then
       (if Result = Ok then
       Count >= Fixed_Fields and then Length = 4 + Count * 4 and then
       (for all I in 1 .. Count => Values (I) = Word (Wire, 4 * I + 1)) and then
       Values = Projection (Wire, Count)
       else Count = 0)
   is
      Used : Field_Count;
   begin
      Values := [others => 0];
      Count := 0;
      Result := Bad_Header;
      if Length < 4 or else Wire (1) /= Character'Pos ('S') or else
        Wire (2) /= Character'Pos ('T') or else
        Wire (3) /= Character'Pos ('T') or else Wire (4) /= Character'Pos ('1')
      then
         return;
      end if;
      Result := Invalid_Model;
      if (Length - 4) mod 4 /= 0 or else
        (Length - 4) / 4 not in Fixed_Fields .. Max_Fields
      then
         return;
      end if;
      Used := (Length - 4) / 4;
      for I in 1 .. Used loop
         Values (I) := Word (Wire, 4 * I + 1);
         pragma Loop_Invariant
           (for all J in 1 .. I => Values (J) = Word (Wire, 4 * J + 1));
         pragma Loop_Invariant (for all J in I + 1 .. Max_Fields => Values (J) = 0);
      end loop;
      Count := Used;
      Result := Ok;
   end Read_Fields;

   procedure Read_Scope
     (Values : Fields; Offset : Natural; Keys : out Scope; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Offset <= Max_Fields - 9,
     Post => ((Result = Ok) = Scope_Valid (Values, Offset)) and then
       (if Result = Ok then Scope_Matches (Values, Offset, Keys) and then
       (Tick (Keys.Source) = Values (Offset + 1) and
       Tick (Keys.Rule) = Values (Offset + 2) and
       Tick (Keys.Instance) = Values (Offset + 3) and
       Tick (Keys.Trigger) = Values (Offset + 4) and
       Tick (Keys.Actor) = Values (Offset + 5) and
       Tick (Keys.Subject) = Values (Offset + 6) and
       Tick (Keys.Action) = Values (Offset + 7) and
       Tick (Keys.Clock) = Values (Offset + 8) and
       Tick (Keys.Binding) = Values (Offset + 9))
       else Keys = Scope'(others => 0))
   is
   begin
      Keys := (others => 0);
      Result := Invalid_Model;
      for I in 1 .. 9 loop
         if Values (Offset + I) > Tick (Reference'Last) then
            return;
         end if;
         pragma Loop_Invariant
           (for all J in 1 .. I => Values (Offset + J) <= Tick (Reference'Last));
      end loop;
      Keys := (Source => Reference (Values (Offset + 1)),
               Rule => Reference (Values (Offset + 2)),
               Instance => Reference (Values (Offset + 3)),
               Trigger => Reference (Values (Offset + 4)),
               Actor => Reference (Values (Offset + 5)),
               Subject => Reference (Values (Offset + 6)),
               Action => Reference (Values (Offset + 7)),
               Clock => Reference (Values (Offset + 8)),
               Binding => Reference (Values (Offset + 9)));
      Result := Ok;
   end Read_Scope;

   procedure Read_Base (Values : Fields; Item : in out Model; Result : out Status)
   with Global => null, Always_Terminates,
     Post => ((Result = Ok) = Base_Valid (Values)) and then
       Item.Observed = Item.Observed'Old and then Item.History = Item.History'Old and then
       (if Result = Ok then Base_Matches (Values, Item))
   is
   begin
      Read_Scope (Values, 0, Item.Keys, Result);
      if Result /= Ok then
         return;
      end if;
      Result := Invalid_Model;
      if Values (10) > Time_Unit'Pos (Time_Unit'Last) or
        Values (11) > Modality'Pos (Modality'Last) or
        Values (15) > Inclusion'Pos (Closed) or Values (16) > Inclusion'Pos (Closed) or
        Values (17) > Tick (Reference'Last) or
        Values (18) > Truth'Pos (Known_True) or
        Values (19) > Tick (Reference'Last) or Values (20) > Max_Events
      then
         return;
      end if;
      Item.Unit := Time_Unit'Val (Values (10));
      Item.Mode := Modality'Val (Values (11));
      Item.First := Values (12);
      Item.Last := Values (13);
      Item.Now := Values (14);
      Item.Lower := Inclusion'Val (Values (15));
      Item.Upper := Inclusion'Val (Values (16));
      Item.Trigger_Evidence := Reference (Values (17));
      Item.Exception_State := Truth'Val (Values (18));
      Item.Exception_Evidence := Reference (Values (19));
      Item.Count := Event_Count (Values (20));
      Result := Ok;
   end Read_Base;

   procedure Read_Coverage
     (Values : Fields; Observed : out Coverage; Result : out Status)
   with Global => null, Always_Terminates,
     Post => ((Result = Ok) = Transport_Temporal_Format.Coverage_Valid (Values)) and then
       (if Result = Ok then Coverage_Matches (Values, Observed))
   is
   begin
      Observed := (others => <>);
      Read_Scope (Values, 20, Observed.Keys, Result);
      if Result /= Ok then
         return;
      end if;
      Result := Invalid_Model;
      if Values (30) > Time_Unit'Pos (Time_Unit'Last) or
        Values (33) > Inclusion'Pos (Closed) or Values (34) > Inclusion'Pos (Closed) or
        Values (35) > Tick (Reference'Last)
      then
         return;
      end if;
      Observed.Unit := Time_Unit'Val (Values (30));
      Observed.First := Values (31);
      Observed.Last := Values (32);
      Observed.Lower := Inclusion'Val (Values (33));
      Observed.Upper := Inclusion'Val (Values (34));
      Observed.Evidence := Reference (Values (35));
      Result := Ok;
   end Read_Coverage;

   procedure Read_Event
     (Values : Fields; Offset : Natural;
      Event : out Observation; Result : out Status)
   with Global => null, Always_Terminates,
     Pre => Offset <= Max_Fields - Event_Fields,
     Post => ((Result = Ok) = Event_Valid (Values, Offset)) and then
       (if Result = Ok then Event_Matches (Values, Offset, Event))
   is
   begin
      Event := (others => <>);
      Read_Scope (Values, Offset + 1, Event.Keys, Result);
      if Result /= Ok then
         return;
      end if;
      Result := Invalid_Model;
      if Values (Offset + 1) > Tick (Reference'Last) or
        Values (Offset + 11) > Time_Unit'Pos (Time_Unit'Last) or
        Values (Offset + 13) > Tick (Reference'Last)
      then
         return;
      end if;
      Event.Id := Reference (Values (Offset + 1));
      Event.Unit := Time_Unit'Val (Values (Offset + 11));
      Event.At_Time := Values (Offset + 12);
      Event.Evidence := Reference (Values (Offset + 13));
      Result := Ok;
   end Read_Event;

   procedure Read_History
     (Values : Fields; Count : Event_Count;
      History : out Event_Array; Result : out Status)
   with Global => null, Always_Terminates,
     Post => ((Result = Ok) =
       (for all I in 1 .. Count =>
          Event_Valid (Values, Fixed_Fields + (I - 1) * Event_Fields))) and then
       (if Result = Ok then
          (for all I in 1 .. Count =>
             Event_Matches (Values, Fixed_Fields + (I - 1) * Event_Fields, History (I)))) and then
       (for all I in Count + 1 .. Max_Events => History (I) = Observation'(others => <>))
   is
   begin
      History := [others => (others => <>)];
      Result := Ok;
      for I in 1 .. Count loop
         Read_Event
           (Values, Fixed_Fields + (I - 1) * Event_Fields, History (I), Result);
         if Result /= Ok then
            return;
         end if;
         pragma Loop_Invariant (Result = Ok);
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              Event_Valid (Values, Fixed_Fields + (J - 1) * Event_Fields));
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              Event_Matches (Values, Fixed_Fields + (J - 1) * Event_Fields, History (J)));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Events => History (J) = Observation'(others => <>));
      end loop;
   end Read_History;

   procedure Read_Model
     (Wire : Wire_Buffer; Length : Wire_Length;
      Item : out Model; Result : out Status)
   is
      Values : Fields;
      Count : Field_Count;
      Candidate : Model;
   begin
      Item := (others => <>);
      Read_Fields (Wire, Length, Values, Count, Result);
      if Result /= Ok then
         return;
      end if;
      Prove_Frame_Validity (Wire, Length, Values, Count);
      Read_Base (Values, Candidate, Result);
      if Result /= Ok then
         return;
      end if;
      if Count /= Fixed_Fields + Candidate.Count * Event_Fields then
         Result := Invalid_Model;
         return;
      end if;
      Read_Coverage (Values, Candidate.Observed, Result);
      if Result /= Ok then
         return;
      end if;
      Read_History (Values, Candidate.Count, Candidate.History, Result);
      if Result /= Ok then
         return;
      end if;
      pragma Assert (Fields_Match (Values, Candidate));
      Item := Candidate;
      Result := Ok;
   end Read_Model;
end Transport_Temporal_Parse;

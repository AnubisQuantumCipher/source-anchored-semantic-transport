package Transport_Temporal with SPARK_Mode is
   Max_Events : constant := 64;
   subtype Reference is Natural range 0 .. 65_535;
   type Tick is range 0 .. 4_294_967_295;
   type Modality is (Mandatory, Prohibited, Recommended, Permitted, Other);
   type Time_Unit is (Unknown_Unit, Nanosecond, Microsecond, Millisecond, Second);
   type Inclusion is (Open, Closed);
   type Truth is (Unresolved, Known_False, Known_True);
   type Outcome is (Not_Evaluated, Unknown, Exempt, Satisfied, Violated, Pending);
   subtype Event_Count is Natural range 0 .. Max_Events;
   subtype Event_Index is Positive range 1 .. Max_Events;
   type Scope is record
      Source, Rule, Instance, Trigger, Actor, Subject, Action, Clock, Binding :
        Reference := 0;
   end record;
   type Observation is record
      Id : Reference := 0;
      Keys : Scope;
      Unit : Time_Unit := Unknown_Unit;
      At_Time : Tick := 0;
      Evidence : Reference := 0;
   end record;
   type Event_Array is array (Event_Index) of Observation;
   type Coverage is record
      Keys : Scope;
      Unit : Time_Unit := Unknown_Unit;
      First, Last : Tick := 0;
      Lower, Upper : Inclusion := Open;
      Evidence : Reference := 0;
   end record;
   type Model is record
      Keys : Scope;
      Unit : Time_Unit := Unknown_Unit;
      Mode : Modality := Other;
      First, Last, Now : Tick := 0;
      Lower, Upper : Inclusion := Open;
      Trigger_Evidence : Reference := 0;
      Exception_State : Truth := Unresolved;
      Exception_Evidence : Reference := 0;
      Count : Event_Count := 0;
      History : Event_Array;
      Observed : Coverage;
   end record;

   function Known (Keys : Scope) return Boolean
   with Global => null,
     Post => Known'Result =
       (Keys.Source > 0 and Keys.Rule > 0 and Keys.Instance > 0 and
        Keys.Trigger > 0 and Keys.Actor > 0 and Keys.Subject > 0 and
        Keys.Action > 0 and Keys.Clock > 0 and Keys.Binding > 0);

   function Admitted (Item : Model) return Boolean
   with Global => null,
     Post => Admitted'Result =
       (Known (Item.Keys) and Item.Unit /= Unknown_Unit and
        Item.Trigger_Evidence > 0 and Item.First <= Item.Last and
        Item.First <= Item.Now and
        (for all I in 1 .. Item.Count =>
           Item.History (I).Id > 0 and Item.History (I).Evidence > 0 and
           Item.History (I).Keys = Item.Keys and
           Item.History (I).Unit = Item.Unit and
           Item.History (I).At_Time <= Item.Now and
           (for all J in 1 .. I - 1 =>
              Item.History (I).Id /= Item.History (J).Id)));

   function In_Window (Item : Model; At_Time : Tick) return Boolean
   with Global => null,
     Post => In_Window'Result =
       ((At_Time > Item.First or
         (At_Time = Item.First and Item.Lower = Closed)) and
        (At_Time < Item.Last or
         (At_Time = Item.Last and Item.Upper = Closed)));

   function Empty
     (First, Last : Tick; Lower, Upper : Inclusion) return Boolean
   with Global => null,
     Post => Empty'Result =
       (First > Last or else
        (First = Last and then (Lower = Open or Upper = Open)) or else
        (First < Last and then Lower = Open and then Upper = Open and then
         Last - First = 1));

   function Last_Point
     (First, Last : Tick; Lower, Upper : Inclusion) return Tick
   with Global => null,
     Pre => not Empty (First, Last, Lower, Upper),
     Post => Last_Point'Result = (if Upper = Closed then Last else Last - 1);

   function First_Point
     (First, Last : Tick; Lower, Upper : Inclusion) return Tick
   with Global => null,
     Pre => not Empty (First, Last, Lower, Upper),
     Post => First_Point'Result = (if Lower = Closed then First else First + 1);

   function Witness (Item : Model) return Boolean
   with Global => null,
     Post => Witness'Result =
       (for some I in 1 .. Item.Count =>
          In_Window (Item, Item.History (I).At_Time)) and then
       (if Empty (Item.First, Item.Last, Item.Lower, Item.Upper) then
          not Witness'Result);

   function Coverage_Valid (Item : Model) return Boolean
   with Global => null,
     Post => Coverage_Valid'Result =
       (Item.Observed.Evidence > 0 and Item.Observed.Keys = Item.Keys and
        Item.Observed.Unit = Item.Unit and
        Item.Observed.First <= Item.Observed.Last and
        Item.Observed.Last <= Item.Now);

   function Whole_Window (Item : Model) return Boolean
   with Global => null,
     Post => Whole_Window'Result =
       (Empty (Item.First, Item.Last, Item.Lower, Item.Upper) or else
        (Coverage_Valid (Item) and then
         not Empty (Item.Observed.First, Item.Observed.Last,
                    Item.Observed.Lower, Item.Observed.Upper) and then
         First_Point (Item.Observed.First, Item.Observed.Last,
                      Item.Observed.Lower, Item.Observed.Upper) <=
           First_Point (Item.First, Item.Last, Item.Lower, Item.Upper) and then
         Last_Point (Item.Observed.First, Item.Observed.Last,
                     Item.Observed.Lower, Item.Observed.Upper) >=
           Last_Point (Item.First, Item.Last, Item.Lower, Item.Upper)));

   function Open_Prefix (Item : Model) return Boolean
   with Global => null,
     Post => Open_Prefix'Result =
       (not Empty (Item.First, Item.Last, Item.Lower, Item.Upper) and then
        Coverage_Valid (Item) and then not Whole_Window (Item) and then
        Item.Observed.Last = Item.Now and then
        Item.Now <= Last_Point (Item.First, Item.Last, Item.Lower, Item.Upper) and then
        (Item.Now < First_Point (Item.First, Item.Last, Item.Lower, Item.Upper) or else
         (Item.Now = First_Point (Item.First, Item.Last, Item.Lower, Item.Upper) and then
          Item.Observed.Upper = Open) or else
         (not Empty (Item.Observed.First, Item.Observed.Last,
                     Item.Observed.Lower, Item.Observed.Upper) and then
          First_Point (Item.Observed.First, Item.Observed.Last,
                       Item.Observed.Lower, Item.Observed.Upper) <=
            First_Point (Item.First, Item.Last, Item.Lower, Item.Upper))));

   procedure Prove_Empty_Exclusion (Item : Model; At_Time : Tick)
   with Ghost, Global => null, Always_Terminates,
     Pre => Empty (Item.First, Item.Last, Item.Lower, Item.Upper),
     Post => not In_Window (Item, At_Time);

   procedure Prove_Whole_Coverage (Item : Model; At_Time : Tick)
   with Ghost, Global => null, Always_Terminates,
     Pre => Whole_Window (Item) and In_Window (Item, At_Time),
     Post => Coverage_Valid (Item) and
       (At_Time > Item.Observed.First or
        (At_Time = Item.Observed.First and Item.Observed.Lower = Closed)) and
       (At_Time < Item.Observed.Last or
        (At_Time = Item.Observed.Last and Item.Observed.Upper = Closed));

   function Evaluate (Item : Model) return Outcome
   with Global => null,
     Post => Evaluate'Result =
       (if Item.Mode not in Mandatory | Prohibited then Not_Evaluated
        elsif not Admitted (Item) or Item.Exception_State = Unresolved or
          Item.Exception_Evidence = 0 then Unknown
        elsif Item.Exception_State = Known_True then Exempt
        elsif Witness (Item) then
          (if Item.Mode = Mandatory then Satisfied else Violated)
        elsif Whole_Window (Item) then
          (if Item.Mode = Mandatory then Violated else Satisfied)
        elsif Open_Prefix (Item) then Pending
        else Unknown);
end Transport_Temporal;

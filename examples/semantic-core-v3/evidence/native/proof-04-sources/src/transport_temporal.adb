package body Transport_Temporal with SPARK_Mode is
   function Known (Keys : Scope) return Boolean is
   begin
      return Keys.Source > 0 and Keys.Rule > 0 and Keys.Instance > 0 and
        Keys.Trigger > 0 and Keys.Actor > 0 and Keys.Subject > 0 and
        Keys.Action > 0 and Keys.Clock > 0 and Keys.Binding > 0;
   end Known;

   function Admitted (Item : Model) return Boolean is
   begin
      return Known (Item.Keys) and Item.Unit /= Unknown_Unit and
        Item.Trigger_Evidence > 0 and Item.First <= Item.Last and
        Item.First <= Item.Now and
        (for all I in 1 .. Item.Count =>
           Item.History (I).Id > 0 and Item.History (I).Evidence > 0 and
           Item.History (I).Keys = Item.Keys and
           Item.History (I).Unit = Item.Unit and
           Item.History (I).At_Time <= Item.Now and
           (for all J in 1 .. I - 1 =>
              Item.History (I).Id /= Item.History (J).Id));
   end Admitted;

   function In_Window (Item : Model; At_Time : Tick) return Boolean is
   begin
      return (At_Time > Item.First or
              (At_Time = Item.First and Item.Lower = Closed)) and
        (At_Time < Item.Last or
         (At_Time = Item.Last and Item.Upper = Closed));
   end In_Window;

   function Empty
     (First, Last : Tick; Lower, Upper : Inclusion) return Boolean
   is
   begin
      return First > Last or else
        (First = Last and then (Lower = Open or Upper = Open)) or else
        (First < Last and then Lower = Open and then Upper = Open and then
         Last - First = 1);
   end Empty;

   function Last_Point
     (First, Last : Tick; Lower, Upper : Inclusion) return Tick
   is
   begin
      return (if Upper = Closed then Last else Last - 1);
   end Last_Point;

   function First_Point
     (First, Last : Tick; Lower, Upper : Inclusion) return Tick
   is
   begin
      return (if Lower = Closed then First else First + 1);
   end First_Point;

   function Witness (Item : Model) return Boolean is
   begin
      for I in 1 .. Item.Count loop
         if In_Window (Item, Item.History (I).At_Time) then
            return True;
         end if;
         pragma Loop_Invariant
           (for all J in 1 .. I =>
              not In_Window (Item, Item.History (J).At_Time));
      end loop;
      return False;
   end Witness;

   function Coverage_Valid (Item : Model) return Boolean is
   begin
      return Item.Observed.Evidence > 0 and Item.Observed.Keys = Item.Keys and
        Item.Observed.Unit = Item.Unit and
        Item.Observed.First <= Item.Observed.Last and
        Item.Observed.Last <= Item.Now;
   end Coverage_Valid;

   function Whole_Window (Item : Model) return Boolean is
   begin
      return Empty (Item.First, Item.Last, Item.Lower, Item.Upper) or else
        (Coverage_Valid (Item) and then
         not Empty (Item.Observed.First, Item.Observed.Last,
                    Item.Observed.Lower, Item.Observed.Upper) and then
         First_Point (Item.Observed.First, Item.Observed.Last,
                      Item.Observed.Lower, Item.Observed.Upper) <=
           First_Point (Item.First, Item.Last, Item.Lower, Item.Upper) and then
         Last_Point (Item.Observed.First, Item.Observed.Last,
                     Item.Observed.Lower, Item.Observed.Upper) >=
           Last_Point (Item.First, Item.Last, Item.Lower, Item.Upper));
   end Whole_Window;

   function Open_Prefix (Item : Model) return Boolean is
   begin
      return not Empty (Item.First, Item.Last, Item.Lower, Item.Upper) and then
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
            First_Point (Item.First, Item.Last, Item.Lower, Item.Upper)));
   end Open_Prefix;

   procedure Prove_Empty_Exclusion (Item : Model; At_Time : Tick) is
   begin
      null;
   end Prove_Empty_Exclusion;

   procedure Prove_Whole_Coverage (Item : Model; At_Time : Tick) is
   begin
      null;
   end Prove_Whole_Coverage;

   function Evaluate (Item : Model) return Outcome is
   begin
      if Item.Mode not in Mandatory | Prohibited then
         return Not_Evaluated;
      elsif not Admitted (Item) or Item.Exception_State = Unresolved or
        Item.Exception_Evidence = 0
      then
         return Unknown;
      elsif Item.Exception_State = Known_True then
         return Exempt;
      elsif Witness (Item) then
         return (if Item.Mode = Mandatory then Satisfied else Violated);
      elsif Whole_Window (Item) then
         return (if Item.Mode = Mandatory then Violated else Satisfied);
      elsif Open_Prefix (Item) then
         return Pending;
      else
         return Unknown;
      end if;
   end Evaluate;
end Transport_Temporal;

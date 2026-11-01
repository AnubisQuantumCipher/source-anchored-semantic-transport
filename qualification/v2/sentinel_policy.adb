package body Sentinel_Policy with SPARK_Mode is
   function Identity_Valid (Held : Identity) return Boolean is
     ((for all P in Pin_Kind => Held.Hashes (P) /= Zero_Digest)
      and then Held.Source_Bytes > 0
      and then Held.Region_Start < Held.Region_End
      and then Held.Region_End <= Held.Reading_Bytes
      and then Held.Region_End - Held.Region_Start <= Max_Region);

   function Roster_Valid
     (Roster : Questions; C : Claim_Count; P : Probe_Count) return Boolean is
     (C > 0 and then P > 0 and then
      (for all I in 1 .. P => Roster (I).Subject in 1 .. C
       and then Roster (I).Input_Pin /= Zero_Digest
       and then Roster (I).Expected_Answer /= Zero_Digest));

   function Link_Valid (Link : Source_Link; Held : Identity) return Boolean is
     (Link.First < Link.Last and then
       (case Link.Kind is
          when Original_Source =>
            Link.Anchor = Held.Hashes (Source_Pin)
            and then Link.Last <= Held.Source_Bytes,
          when Reading_View =>
            Link.Anchor = Held.Hashes (Reading_Pin)
            and then Link.First >= Held.Region_Start
            and then Link.Last <= Held.Region_End));

   function Claims_Valid
     (Evidence : Claims; Count : Claim_Count; Held : Identity) return Boolean is
     ((for all C in 1 .. Count =>
        (for all L in 1 .. Evidence (C).Count =>
           Link_Valid (Evidence (C).Evidence (L), Held))));

   function All_Linked (Evidence : Claims; Count : Claim_Count)
     return Boolean is
     ((for all C in 1 .. Count => Evidence (C).Count > 0));

   function Repairs_Valid (Item : Session) return Boolean is
     ((for all R in Round_Id =>
        (if R in 2 .. Item.Round then Item.Repairs (R) /= Zero_Digest
          and then (for all Prior in Round_Id =>
            (for all P in Probe_Id => Item.Parents (R) (Prior, P) =
              (Prior < R and then Item.Failures (Prior, P)))))));

   function New_Candidate (Item : Session; Candidate : Digest)
     return Boolean is
     ((for all R in 1 .. Item.Round => Item.Candidates (R) /= Candidate));

   function Answer_Admissible
     (Item : Session; Ordinal : Probe_Id; Observed : Identity;
      Candidate, Actual_Answer, Receipt : Digest) return Boolean is
     (not Item.Poisoned and then Observed = Item.Held
      and then Candidate = Item.Candidates (Item.Round)
      and then Ordinal <= Item.Probe_Total
      and then Item.Counts (Item.Round) < Item.Probe_Total
      and then Ordinal = Item.Counts (Item.Round) + 1
      and then Actual_Answer /= Zero_Digest and then Receipt /= Zero_Digest);

   function Refinement_Admissible
     (Item : Session; Candidate, Repair : Digest; Parents : Failure_Mask)
     return Boolean is
     (not Item.Poisoned and then Item.Round < Max_Rounds
      and then Candidate /= Zero_Digest and then Repair /= Zero_Digest
      and then New_Candidate (Item, Candidate) and then Parents = Item.Failures);

   function Result_Of (Item : Session; Round : Round_Id; Id : Probe_Id)
     return Answer_Result is
     (if not Item.Data (Round, Id).Present then Missing
      elsif Item.Data (Round, Id).Actual = Item.Roster (Id).Expected_Answer
      then Matches else Differs);

   function All_Match (Item : Session) return Boolean is
     (Item.Counts (Item.Round) = Item.Probe_Total and then
      (for all P in 1 .. Item.Probe_Total =>
         Result_Of (Item, Item.Round, P) = Matches
         and then Item.Data (Item.Round, P).Obstruction = No_Blocker));

   function Eligible (Item : Session) return Boolean is
     (Valid (Item) and then Item.Started and then not Item.Poisoned
      and then Identity_Valid (Item.Held)
      and then Roster_Valid (Item.Roster, Item.Claim_Total, Item.Probe_Total)
      and then Item.Bound_Recorded (Item.Round)
      and then Item.Bound_OK (Item.Round)
      and then Item.Context_OK (Item.Round)
      and then Item.Adjudication_OK (Item.Round)
      and then Repairs_Valid (Item) and then All_Match (Item));

   function Current_Differs (Item : Session) return Boolean is
     ((for some P in 1 .. Item.Probe_Total =>
        Result_Of (Item, Item.Round, P) = Differs));

   function Current_Challenge (Item : Session) return Boolean is
     ((for some P in 1 .. Item.Counts (Item.Round) =>
        Item.Data (Item.Round, P).Obstruction = Open_Challenge));

   function State_Of (Item : Session) return Interpretation_State is
     (if Item.Requested and then Eligible (Item) then Qualified_For_Q
      elsif Item.Poisoned or else Current_Differs (Item) then Rejected
      elsif Current_Challenge (Item) then Challenged
      elsif Item.Requested then Unresolved
      elsif Item.Bound_Recorded (Item.Round)
        and then Item.Bound_OK (Item.Round) then Source_Bound
      else Proposed);

   function Failure_Count (Item : Session) return Event_Count is
      Count : Event_Count := 0;
   begin
      for R in Round_Id loop
         for P in Probe_Id loop
            pragma Loop_Invariant
              (Count <= ((R - 1) * Max_Probes + (P - 1)));
            pragma Loop_Invariant
              (if (for all X in Round_Id =>
                    (for all Y in Probe_Id => not Item.Failures (X, Y)))
               then Count = 0);
            if Item.Failures (R, P) then
               Count := Count + 1;
            end if;
         end loop;
         pragma Loop_Invariant (Count <= R * Max_Probes);
         pragma Loop_Invariant
           (if (for all X in Round_Id =>
                 (for all Y in Probe_Id => not Item.Failures (X, Y)))
            then Count = 0);
      end loop;
      return Count;
   end Failure_Count;

   procedure Reset_Unstarted (Item : out Session)
     with Global => null, Depends => (Item => null), Always_Terminates,
       Post => Valid (Item) and then Default_Header (Item)
         and then (for all R in Round_Id => Default_Round (Item, R))
   is
   begin
      Item := Default_Session;
   end Reset_Unstarted;

   procedure Initialize
     (Item : in out Session; Held : Identity; Roster : Questions;
      Claim_Total : Claim_Count; Probe_Total : Probe_Count;
      Candidate : Digest) is
   begin
      if Item.Started then
         Item.Poisoned := True;
      else
         Reset_Unstarted (Item);
         Item.Started := True;
         Item.Held := Held;
         Item.Roster := Roster;
         Item.Claim_Total := Claim_Total;
         Item.Probe_Total := Probe_Total;
         Item.Candidates (1) := Candidate;
         Item.Poisoned := not Identity_Valid (Held)
           or else not Roster_Valid (Roster, Claim_Total, Probe_Total)
           or else Candidate = Zero_Digest;
      end if;
   end Initialize;

   procedure Bind_Source
     (Item : in out Session; Observed : Identity; Evidence : Claims;
      Context_Complete, Adjudication_Complete : Boolean) is
   begin
      if Item.Poisoned or else Observed /= Item.Held
        or else Item.Bound_Recorded (Item.Round)
        or else not Claims_Valid (Evidence, Item.Claim_Total, Item.Held)
      then
         Item.Poisoned := True;
      else
         Item.Bound_Recorded (Item.Round) := True;
         Item.Bound_OK (Item.Round) := All_Linked (Evidence, Item.Claim_Total);
         Item.Context_OK (Item.Round) := Context_Complete;
         Item.Adjudication_OK (Item.Round) := Adjudication_Complete;
         Item.Claim_History (Item.Round) := Evidence;
         Item.Requested := False;
      end if;
   end Bind_Source;

   procedure Record_Answer
     (Item : in out Session; Ordinal : Probe_Id; Observed : Identity;
      Candidate, Actual_Answer, Receipt : Digest; Obstruction : Blocker) is
   begin
      if not Answer_Admissible
        (Item, Ordinal, Observed, Candidate, Actual_Answer, Receipt) then
         Item.Poisoned := True;
      else
         Item.Data (Item.Round, Ordinal) :=
           (True, Actual_Answer, Receipt, Obstruction);
         Item.Counts (Item.Round) := Item.Counts (Item.Round) + 1;
         Item.Failures (Item.Round, Ordinal) :=
           Actual_Answer /= Item.Roster (Ordinal).Expected_Answer
           or else Obstruction /= No_Blocker;
         Item.Requested := False;
      end if;
   end Record_Answer;

   procedure Request_Qualification (Item : in out Session) is
   begin
      Item.Requested := True;
      pragma Assert (Qualification_Requested (Item));
      declare
         Current_State : constant Interpretation_State := State_Of (Item);
         Is_Eligible : constant Boolean := Eligible (Item);
      begin
         pragma Assert
           ((Current_State = Qualified_For_Q) =
              (Qualification_Requested (Item) and then Is_Eligible));
         pragma Assert ((Current_State = Qualified_For_Q) = Is_Eligible);
      end;
   end Request_Qualification;

   procedure Begin_Refinement
     (Item : in out Session; Candidate, Repair : Digest;
      Parents : Failure_Mask) is
   begin
      if not Refinement_Admissible (Item, Candidate, Repair, Parents) then
         Item.Poisoned := True;
      else
         Item.Round := Item.Round + 1;
         Item.Candidates (Item.Round) := Candidate;
         Item.Repairs (Item.Round) := Repair;
         Item.Parents (Item.Round) := Parents;
         Item.Requested := False;
      end if;
   end Begin_Refinement;
end Sentinel_Policy;

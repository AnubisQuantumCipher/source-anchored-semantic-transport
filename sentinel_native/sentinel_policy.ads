package Sentinel_Policy with SPARK_Mode, Pure is
   Max_Claims : constant := 64;
   Max_Probes : constant := 256;
   Max_Rounds : constant := 8;
   Max_Links : constant := 16;
   Max_Region : constant := 65_536;
   Max_Source : constant := 1_073_741_824;
   Max_Reading : constant := 33_554_432;
   subtype Claim_Count is Natural range 0 .. Max_Claims;
   subtype Claim_Id is Claim_Count range 1 .. Max_Claims;
   subtype Probe_Count is Natural range 0 .. Max_Probes;
   subtype Probe_Id is Probe_Count range 1 .. Max_Probes;
   subtype Round_Id is Positive range 1 .. Max_Rounds;
   subtype Link_Count is Natural range 0 .. Max_Links;
   subtype Link_Id is Link_Count range 1 .. Max_Links;
   subtype Byte_Count is Natural range 0 .. Max_Source;
   subtype Reading_Count is Byte_Count range 0 .. Max_Reading;
   subtype Event_Count is Natural range 0 .. Max_Rounds * Max_Probes;
   type Octet is mod 256 with Size => 8;
   type Digest is array (Positive range 1 .. 32) of Octet;
   Zero_Digest : constant Digest := [others => 0];
   type Pin_Kind is
     (Source_Pin, Package_Pin, Reading_Pin, Metadata_Pin, Policy_Pin,
      Questions_Pin, Oracle_Pin, Reference_Pin, Evaluator_Pin);
   type Pins is array (Pin_Kind) of Digest;
   type Identity is record
      Hashes : Pins := [others => Zero_Digest];
      Source_Bytes : Byte_Count := 0;
      Reading_Bytes : Reading_Count := 0;
      Region_Start, Region_End : Reading_Count := 0;
   end record;
   type Documentary_State is
     (Supported_Only, Refuted_Only, Both, Neither);
   type Representation is (Original_Source, Reading_View);
   type Source_Link is record
      Kind : Representation := Reading_View;
      Anchor : Digest := Zero_Digest;
      First, Last : Byte_Count := 0;
   end record;
   type Links is array (Link_Id) of Source_Link;
   type Claim is record
      Documentary : Documentary_State := Neither;
      Count : Link_Count := 0;
      Evidence : Links := [others => <>];
   end record;
   type Claims is array (Claim_Id) of Claim;
   type Question is record
      Subject : Claim_Count := 0;
      Input_Pin, Expected_Answer : Digest := Zero_Digest;
   end record;
   type Questions is array (Probe_Id) of Question;
   type Blocker is
     (No_Blocker, Required_Unresolved, Required_Conflict, Open_Challenge);
   type Interpretation_State is
     (Proposed, Source_Bound, Challenged, Qualified_For_Q,
      Opaque, Unresolved, Rejected);
   type Execution_Authority is (None);
   type Answer_Result is (Missing, Matches, Differs);
   type Failure_Mask is array (Round_Id, Probe_Id) of Boolean;
   type Session is private
     with Default_Initial_Condition => Valid (Session);

   function Valid (Item : Session) return Boolean with Global => null;
   function Initialized (Item : Session) return Boolean with Global => null;
   function Identity_Of (Item : Session) return Identity with Global => null;
   function Questions_Of (Item : Session) return Questions with Global => null;
   function Current_Round (Item : Session) return Round_Id with Global => null;
   function Candidate_Of (Item : Session) return Digest with Global => null;
   function Accepted_Count (Item : Session) return Probe_Count
     with Global => null;
   function Expected_Of (Item : Session; Id : Probe_Id) return Digest
     with Global => null;
   function Qualification_Requested (Item : Session) return Boolean
     with Global => null;
   function Fatal (Item : Session) return Boolean with Global => null;
   function Eligible (Item : Session) return Boolean with Global => null;
   function State_Of (Item : Session) return Interpretation_State
     with Global => null,
       Post => (State_Of'Result = Qualified_For_Q) =
         (Qualification_Requested (Item) and then Eligible (Item));
   function Authority return Execution_Authority is (None)
     with Global => null;
   function Failure_History (Item : Session) return Failure_Mask
     with Global => null;
   function Failure_Count (Item : Session) return Event_Count
     with Global => null,
       Post => (if (for all R in Round_Id =>
                    (for all P in Probe_Id =>
                       not Failure_History (Item) (R, P)))
                then Failure_Count'Result = 0);
   function Documentary_Of (Item : Session; Id : Claim_Id)
     return Documentary_State with Global => null;
   function Result_Of (Item : Session; Round : Round_Id; Id : Probe_Id)
     return Answer_Result with Global => null;
   function History_Preserved (Before, After : Session) return Boolean
     with Global => null;
   function Answer_Admissible
     (Item : Session; Ordinal : Probe_Id; Observed : Identity;
      Candidate, Actual_Answer, Receipt : Digest) return Boolean
     with Global => null;
   function Refinement_Admissible
     (Item : Session; Candidate, Repair : Digest; Parents : Failure_Mask)
     return Boolean with Global => null;

   procedure Initialize
     (Item : in out Session; Held : Identity; Roster : Questions;
      Claim_Total : Claim_Count; Probe_Total : Probe_Count;
      Candidate : Digest)
   with Global => null,
     Depends => (Item => (Item, Held, Roster, Claim_Total, Probe_Total,
                         Candidate)), Always_Terminates,
     Pre => Valid (Item),
     Post => Valid (Item) and Initialized (Item)
       and (if Initialized (Item'Old) then Fatal (Item)
         and Identity_Of (Item) = Identity_Of (Item'Old)
         and Questions_Of (Item) = Questions_Of (Item'Old)
         and History_Preserved (Item'Old, Item)
         and Failure_History (Item) = Failure_History (Item'Old)
       else Identity_Of (Item) = Held and Questions_Of (Item) = Roster
         and Current_Round (Item) = 1
         and Failure_Count (Item) = 0);

   procedure Bind_Source
     (Item : in out Session; Observed : Identity; Evidence : Claims;
      Context_Complete, Adjudication_Complete : Boolean)
   with Global => null,
     Depends => (Item => (Item, Observed, Evidence, Context_Complete,
                         Adjudication_Complete)), Always_Terminates,
     Pre => Valid (Item) and Initialized (Item),
     Post => Valid (Item) and Identity_Of (Item) = Identity_Of (Item'Old)
       and Questions_Of (Item) = Questions_Of (Item'Old)
       and History_Preserved (Item'Old, Item)
       and Failure_History (Item) = Failure_History (Item'Old);

   procedure Record_Answer
     (Item : in out Session; Ordinal : Probe_Id; Observed : Identity;
      Candidate, Actual_Answer, Receipt : Digest; Obstruction : Blocker)
   with Global => null,
     Depends => (Item => (Item, Ordinal, Observed, Candidate, Actual_Answer,
                         Receipt, Obstruction)), Always_Terminates,
     Pre => Valid (Item) and Initialized (Item),
     Post => Valid (Item) and Identity_Of (Item) = Identity_Of (Item'Old)
       and Questions_Of (Item) = Questions_Of (Item'Old)
       and Current_Round (Item) = Current_Round (Item'Old)
       and History_Preserved (Item'Old, Item)
       and (if Answer_Admissible (Item'Old, Ordinal, Observed,
                                 Candidate, Actual_Answer, Receipt)
         then Accepted_Count (Item) = Accepted_Count (Item'Old) + 1
           and Result_Of (Item, Current_Round (Item), Ordinal) =
             (if Actual_Answer = Expected_Of (Item, Ordinal)
              then Matches else Differs)
         else Fatal (Item)
           and Accepted_Count (Item) = Accepted_Count (Item'Old)
           and Failure_History (Item) = Failure_History (Item'Old))
       and (for all R in Round_Id =>
         (for all P in Probe_Id =>
           (if Failure_History (Item'Old) (R, P) then
              Failure_History (Item) (R, P))));

   procedure Request_Qualification (Item : in out Session)
   with Global => null, Depends => (Item => Item), Always_Terminates,
     Pre => Valid (Item) and Initialized (Item),
     Post => Valid (Item) and Identity_Of (Item) = Identity_Of (Item'Old)
       and Questions_Of (Item) = Questions_Of (Item'Old)
       and History_Preserved (Item'Old, Item)
       and Failure_History (Item) = Failure_History (Item'Old)
       and (State_Of (Item) = Qualified_For_Q) = Eligible (Item);

   procedure Begin_Refinement
     (Item : in out Session; Candidate, Repair : Digest;
      Parents : Failure_Mask)
   with Global => null,
     Depends => (Item => (Item, Candidate, Repair, Parents)),
     Always_Terminates, Pre => Valid (Item) and Initialized (Item),
     Post => Valid (Item) and Identity_Of (Item) = Identity_Of (Item'Old)
       and Questions_Of (Item) = Questions_Of (Item'Old)
       and History_Preserved (Item'Old, Item)
       and Failure_History (Item) = Failure_History (Item'Old)
       and Current_Round (Item) >= Current_Round (Item'Old)
       and (if Refinement_Admissible (Item'Old, Candidate, Repair, Parents)
         then Current_Round (Item) = Current_Round (Item'Old) + 1
           and Candidate_Of (Item) = Candidate
           and Accepted_Count (Item) = 0 and not Fatal (Item)
         else Fatal (Item)
           and Current_Round (Item) = Current_Round (Item'Old))
       and State_Of (Item) /= Qualified_For_Q;

private
   type Answer is record
      Present : Boolean := False;
      Actual, Receipt : Digest := Zero_Digest;
      Obstruction : Blocker := No_Blocker;
   end record;
   type Answers is array (Round_Id, Probe_Id) of Answer;
   type Totals is array (Round_Id) of Probe_Count;
   type Round_Pins is array (Round_Id) of Digest;
   type Claims_By_Round is array (Round_Id) of Claims;
   type Flags is array (Round_Id) of Boolean;
   type Parent_History is array (Round_Id) of Failure_Mask;
   type Session is record
      Started, Poisoned, Requested : Boolean := False;
      Held : Identity;
      Roster : Questions;
      Claim_Total : Claim_Count := 0;
      Probe_Total : Probe_Count := 0;
      Round : Round_Id := 1;
      Candidates, Repairs : Round_Pins := [others => Zero_Digest];
      Parents : Parent_History := [others => [others => [others => False]]];
      Bound_Recorded, Bound_OK, Context_OK, Adjudication_OK : Flags :=
        [others => False];
      Claim_History : Claims_By_Round := [others => [others => <>]];
      Data : Answers := [others => [others => <>]];
      Counts : Totals := [others => 0];
      Failures : Failure_Mask := [others => [others => False]];
   end record;

   function Initialized (Item : Session) return Boolean is (Item.Started);
   function Identity_Of (Item : Session) return Identity is (Item.Held);
   function Questions_Of (Item : Session) return Questions is (Item.Roster);
   function Current_Round (Item : Session) return Round_Id is (Item.Round);
   function Candidate_Of (Item : Session) return Digest is
     (Item.Candidates (Item.Round));
   function Accepted_Count (Item : Session) return Probe_Count is
     (Item.Counts (Item.Round));
   function Expected_Of (Item : Session; Id : Probe_Id) return Digest is
     (Item.Roster (Id).Expected_Answer);
   function Qualification_Requested (Item : Session) return Boolean is
     (Item.Requested);
   function Fatal (Item : Session) return Boolean is (Item.Poisoned);
   function Failure_History (Item : Session) return Failure_Mask is
     (Item.Failures);
   function Documentary_Of (Item : Session; Id : Claim_Id)
     return Documentary_State is
     (Item.Claim_History (Item.Round) (Id).Documentary);
   function Valid (Item : Session) return Boolean is
     ((if not Item.Started then Item.Round = 1 and then not Item.Poisoned
         and then (for all R in Round_Id => Item.Counts (R) = 0))
      and then (for all R in Round_Id => Item.Counts (R) <= Item.Probe_Total)
      and then (for all R in Round_Id =>
        (for all P in Probe_Id =>
          Item.Data (R, P).Present = (P <= Item.Counts (R))))
      and then (for all R in Round_Id =>
        (if R > Item.Round then Item.Counts (R) = 0
          and then not Item.Bound_Recorded (R) and then not Item.Bound_OK (R)
          and then not Item.Context_OK (R) and then not Item.Adjudication_OK (R)
          and then Item.Candidates (R) = Zero_Digest
          and then Item.Repairs (R) = Zero_Digest))
      and then (for all R in Round_Id =>
        (for all P in Probe_Id => Item.Failures (R, P) =
          (Item.Data (R, P).Present and then
           (Item.Data (R, P).Actual /= Item.Roster (P).Expected_Answer
            or else Item.Data (R, P).Obstruction /= No_Blocker)))));
   function History_Preserved (Before, After : Session) return Boolean is
     ((for all R in Round_Id =>
        (for all P in Probe_Id =>
          (if Before.Data (R, P).Present then
             After.Data (R, P) = Before.Data (R, P))))
      and then (for all R in 1 .. Before.Round =>
        After.Candidates (R) = Before.Candidates (R)
        and then After.Repairs (R) = Before.Repairs (R)
        and then After.Parents (R) = Before.Parents (R)
        and then
          (if R < Before.Round or else After.Round > Before.Round
             or else Before.Bound_Recorded (R)
           then After.Claim_History (R) = Before.Claim_History (R)
             and then After.Bound_Recorded (R) = Before.Bound_Recorded (R)
             and then After.Bound_OK (R) = Before.Bound_OK (R)
             and then After.Context_OK (R) = Before.Context_OK (R)
             and then After.Adjudication_OK (R) =
               Before.Adjudication_OK (R))
        and then (if R < Before.Round or else After.Round > Before.Round
                  then After.Counts (R) = Before.Counts (R))));
end Sentinel_Policy;

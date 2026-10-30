with Sentinel_Policy; use Sentinel_Policy;

package body Sentinel_Policy_Fixtures is
   function Nibble (C : Character) return Octet is
   begin
      if C in '0' .. '9' then
         return Octet (Character'Pos (C) - Character'Pos ('0'));
      elsif C in 'a' .. 'f' then
         return Octet (Character'Pos (C) - Character'Pos ('a') + 10);
      else
         raise Program_Error with "invalid frozen hex fixture";
      end if;
   end Nibble;

   function Hex (Text : String) return Digest is
      Value : Digest := Zero_Digest;
   begin
      if Text'Length /= 64 then
         raise Program_Error with "frozen hex fixture length";
      end if;
      for I in Value'Range loop
         Value (I) := 16 * Nibble (Text (Text'First + 2 * (I - 1)))
           + Nibble (Text (Text'First + 2 * (I - 1) + 1));
      end loop;
      return Value;
   end Hex;

   function D (Value : Octet) return Digest is ([others => Value]);
   Unknown_Answer : constant Digest := Hex
     ("8d65a4b9eb195d5e86030347c80f76cf5f23d651a73643a82581979d2548c6bb");
   Conflict_Answer : constant Digest := Hex
     ("ec6aa1e9c198e64d96e893cef57b082f75d9c07e26d618282804228784d567c2");
   False_Answer : constant Digest := Hex
     ("48fedf67ec4e048ba539a11e8f6ff8ee0b2584c92998fa3f1b8d041c517d329a");
   True_Answer : constant Digest := Hex
     ("55292a40a74cbebd2c6f92c3d8b83a5c39a0344f79360979f0b9f37fc25b7fc9");
   Held : constant Identity :=
     (Hashes => [others => D (1)], Source_Bytes => 1,
      Reading_Bytes => 1, Region_Start => 0, Region_End => 1);

   function Roster_For (Expected : Digest) return Questions is
     ([others => (Subject => 1, Input_Pin => D (3),
                  Expected_Answer => Expected)]);

   function Evidence_For (State : Documentary_State) return Claims is
      Value : Claims := [others => <>];
   begin
      Value (1).Documentary := State;
      Value (1).Count := 1;
      Value (1).Evidence (1) := (Reading_View, D (1), 0, 1);
      return Value;
   end Evidence_For;

   procedure Start
     (Item : in out Session; Expected : Digest;
      Documentary : Documentary_State; Context : Boolean := True;
      Adjudication : Boolean := True) is
   begin
      Initialize (Item, Held, Roster_For (Expected), 1, 1, D (2));
      pragma Assert (Valid (Item) and then not Fatal (Item));
      Bind_Source (Item, Held, Evidence_For (Documentary),
                   Context, Adjudication);
   end Start;

   procedure Check_Answer
     (Expected, Actual : Digest; Documentary : Documentary_State;
      Expected_State : Interpretation_State) is
      Item : Session;
   begin
      Start (Item, Expected, Documentary);
      Record_Answer (Item, 1, Held, D (2), Actual, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Expected_State);
      pragma Assert (Documentary_Of (Item, 1) = Documentary);
      pragma Assert (Authority = None);
      pragma Assert (Failure_Count (Item) =
                       (if Expected = Actual then 0 else 1));
   end Check_Answer;

   procedure Check_Blocker
     (Context, Adjudication : Boolean; Obstruction : Blocker;
      Expected_State : Interpretation_State) is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither, Context, Adjudication);
      Record_Answer
        (Item, 1, Held, D (2), Unknown_Answer, D (4), Obstruction);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Expected_State);
      pragma Assert (Result_Of (Item, 1, 1) = Matches);
      pragma Assert (Documentary_Of (Item, 1) = Neither);
   end Check_Blocker;

   procedure Missing_Source is
      Item : Session;
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1, 1, D (2));
      Record_Answer
        (Item, 1, Held, D (2), Unknown_Answer, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Unresolved);
   end Missing_Source;

   procedure Missing_Probe is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Unresolved);
      pragma Assert (Result_Of (Item, 1, 1) = Missing);
   end Missing_Probe;

   procedure Repair_Round
     (Item : in out Session; Candidate : Digest) is
   begin
      Begin_Refinement (Item, Candidate, D (9), Failure_History (Item));
      pragma Assert (State_Of (Item) = Proposed);
      Bind_Source (Item, Held, Evidence_For (Neither), True, True);
   end Repair_Round;

   procedure Repair_Retention is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither);
      Record_Answer
        (Item, 1, Held, D (2), False_Answer, D (4), No_Blocker);
      pragma Assert (State_Of (Item) = Rejected);
      Repair_Round (Item, D (5));
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Unresolved);
      Record_Answer
        (Item, 1, Held, D (5), False_Answer, D (4), No_Blocker);
      pragma Assert (Failure_Count (Item) = 2);
      Repair_Round (Item, D (6));
      Record_Answer
        (Item, 1, Held, D (6), Unknown_Answer, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Qualified_For_Q);
      pragma Assert (Current_Round (Item) = 3);
      pragma Assert (Failure_Count (Item) = 2);
      pragma Assert (Result_Of (Item, 1, 1) = Differs);
      pragma Assert (Result_Of (Item, 2, 1) = Differs);
      Initialize (Item, Held, Roster_For (Conflict_Answer), 1, 1, D (2));
      pragma Assert (Fatal (Item) and then State_Of (Item) = Rejected);
      pragma Assert (Questions_Of (Item) = Roster_For (Unknown_Answer));
      pragma Assert (Failure_Count (Item) = 2);
      pragma Assert (Result_Of (Item, 1, 1) = Differs);
   end Repair_Retention;

   procedure Single_Repair is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither);
      Record_Answer
        (Item, 1, Held, D (2), False_Answer, D (4), No_Blocker);
      Repair_Round (Item, D (5));
      Record_Answer
        (Item, 1, Held, D (5), Unknown_Answer, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Qualified_For_Q);
      pragma Assert (Current_Round (Item) = 2);
      pragma Assert (Failure_Count (Item) = 1);
      pragma Assert (Result_Of (Item, 1, 1) = Differs);
   end Single_Repair;

   procedure Missing_Repair_Parent is
      Item : Session;
      Empty : constant Failure_Mask := [others => [others => False]];
   begin
      Start (Item, Unknown_Answer, Neither);
      Record_Answer
        (Item, 1, Held, D (2), False_Answer, D (4), No_Blocker);
      Begin_Refinement (Item, D (5), D (9), Empty);
      pragma Assert (Fatal (Item) and then Failure_Count (Item) = 1);
      pragma Assert (Current_Round (Item) = 1);
      pragma Assert (Result_Of (Item, 1, 1) = Differs);
   end Missing_Repair_Parent;

   procedure Wrong_Identity is
      Item : Session;
      Other : Identity := Held;
   begin
      Start (Item, Unknown_Answer, Neither);
      Other.Hashes (Questions_Pin) := D (99);
      Record_Answer
        (Item, 1, Other, D (2), Unknown_Answer, D (4), No_Blocker);
      pragma Assert (Fatal (Item) and then Failure_Count (Item) = 0);
      pragma Assert (Result_Of (Item, 1, 1) = Missing);
      Begin_Refinement (Item, D (5), D (9), Failure_History (Item));
      pragma Assert (Fatal (Item) and then Current_Round (Item) = 1);
   end Wrong_Identity;

   procedure Duplicate_Answer is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither);
      Record_Answer
        (Item, 1, Held, D (2), Unknown_Answer, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Qualified_For_Q);
      Record_Answer
        (Item, 1, Held, D (2), False_Answer, D (4), No_Blocker);
      pragma Assert (Fatal (Item) and then State_Of (Item) = Rejected);
      pragma Assert (Result_Of (Item, 1, 1) = Matches);
      pragma Assert (Failure_Count (Item) = 0);
   end Duplicate_Answer;

   procedure Round_Boundary is
      Item : Session;
   begin
      Start (Item, Unknown_Answer, Neither);
      for R in Round_Id loop
         Record_Answer
           (Item, 1, Held, Candidate_Of (Item), Unknown_Answer,
            D (4), No_Blocker);
         Request_Qualification (Item);
         pragma Assert (State_Of (Item) = Qualified_For_Q);
         pragma Assert (Current_Round (Item) = R);
         if R < Max_Rounds then
            Repair_Round (Item, D (Octet (R + 2)));
         end if;
      end loop;
      Begin_Refinement (Item, D (99), D (9), Failure_History (Item));
      pragma Assert (Fatal (Item) and then Current_Round (Item) = 8);
   end Round_Boundary;

   procedure Maximum_Roster is
      Item : Session;
      Evidence : Claims := [others => <>];
   begin
      for C in Claim_Id loop
         Evidence (C).Documentary := Both;
         Evidence (C).Count := Max_Links;
         Evidence (C).Evidence := [others => (Reading_View, D (1), 0, 1)];
      end loop;
      Initialize (Item, Held, Roster_For (Conflict_Answer),
                  Max_Claims, Max_Probes, D (2));
      Bind_Source (Item, Held, Evidence, True, True);
      for P in Probe_Id loop
         Record_Answer
           (Item, P, Held, D (2), Conflict_Answer, D (4), No_Blocker);
      end loop;
      Request_Qualification (Item);
      pragma Assert (State_Of (Item) = Qualified_For_Q);
      pragma Assert (Documentary_Of (Item, Max_Claims) = Both);
      pragma Assert (Failure_Count (Item) = 0);
   end Maximum_Roster;

   procedure Full_Failure_Ledger is
      Item : Session;
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1,
                  Max_Probes, D (2));
      Bind_Source (Item, Held, Evidence_For (Neither), True, True);
      for R in Round_Id loop
         for P in Probe_Id loop
            Record_Answer
              (Item, P, Held, Candidate_Of (Item), False_Answer,
               D (4), No_Blocker);
         end loop;
         pragma Assert (State_Of (Item) = Rejected);
         if R < Max_Rounds then
            Repair_Round (Item, D (Octet (R + 2)));
         end if;
      end loop;
      pragma Assert (Failure_Count (Item) = Max_Rounds * Max_Probes);
      Begin_Refinement (Item, D (99), D (9), Failure_History (Item));
      pragma Assert (Fatal (Item));
      pragma Assert (Failure_Count (Item) = Max_Rounds * Max_Probes);
      Record_Answer
        (Item, 1, Held, D (99), Unknown_Answer, D (4), No_Blocker);
      pragma Assert (Result_Of (Item, 1, 1) = Differs);
      pragma Assert (Result_Of (Item, Max_Rounds, Max_Probes) = Differs);
   end Full_Failure_Ledger;

   procedure Empty_Roster is
      Item : Session;
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1, 0, D (2));
      Request_Qualification (Item);
      pragma Assert (Fatal (Item) and then State_Of (Item) = Rejected);
   end Empty_Roster;

   procedure Invalid_Link is
      Item : Session;
      Evidence : Claims := Evidence_For (Neither);
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1, 1, D (2));
      Evidence (1).Evidence (1).Last := 2;
      Bind_Source (Item, Held, Evidence, True, True);
      pragma Assert (Fatal (Item));
      pragma Assert (Identity_Of (Item) = Held);
   end Invalid_Link;

   procedure Missing_Link is
      Item : Session;
      Evidence : constant Claims := [others => <>];
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1, 1, D (2));
      Bind_Source (Item, Held, Evidence, True, True);
      Record_Answer
        (Item, 1, Held, D (2), Unknown_Answer, D (4), No_Blocker);
      Request_Qualification (Item);
      pragma Assert (not Fatal (Item) and then State_Of (Item) = Unresolved);
   end Missing_Link;
   procedure Fresh_Initialization is
      Item : Session;
   begin
      Initialize (Item, Held, Roster_For (Unknown_Answer), 1, 1, D (2));
      pragma Assert (Valid (Item) and then Initialized (Item));
      pragma Assert (not Fatal (Item) and then not Qualification_Requested (Item));
      pragma Assert (Identity_Of (Item) = Held);
      pragma Assert (Questions_Of (Item) = Roster_For (Unknown_Answer));
      pragma Assert (Current_Round (Item) = 1 and then Candidate_Of (Item) = D (2));
      pragma Assert (Accepted_Count (Item) = 0 and then State_Of (Item) = Proposed);
      for R in Round_Id loop
         for P in Probe_Id loop
            pragma Assert (Result_Of (Item, R, P) = Missing);
            pragma Assert (not Failure_History (Item) (R, P));
         end loop;
      end loop;
      for C in Claim_Id loop
         pragma Assert (Documentary_Of (Item, C) = Neither);
      end loop;
   end Fresh_Initialization;

   procedure Run is
   begin
   Fresh_Initialization;
   Check_Answer (Unknown_Answer, Unknown_Answer, Neither, Qualified_For_Q);
   Check_Answer (Conflict_Answer, Conflict_Answer, Both, Qualified_For_Q);
   Check_Answer (Unknown_Answer, False_Answer, Neither, Rejected);
   Check_Answer (Conflict_Answer, True_Answer, Both, Rejected);
   Check_Answer (Unknown_Answer, Unknown_Answer, Refuted_Only, Qualified_For_Q);
   Check_Answer
     (Unknown_Answer, Unknown_Answer, Supported_Only, Qualified_For_Q);
   Check_Blocker (False, True, No_Blocker, Unresolved);
   Check_Blocker (True, False, No_Blocker, Unresolved);
   Check_Blocker (True, True, Open_Challenge, Challenged);
   Check_Blocker (True, True, Required_Unresolved, Unresolved);
   Check_Blocker (True, True, Required_Conflict, Unresolved);
   Missing_Source;
   Missing_Probe;
   Repair_Retention;
   Single_Repair;
   Missing_Repair_Parent;
   Wrong_Identity;
   Duplicate_Answer;
   Round_Boundary;
   Maximum_Roster;
   Full_Failure_Ledger;
   Empty_Roster;
   Invalid_Link;
   Missing_Link;
   end Run;
end Sentinel_Policy_Fixtures;

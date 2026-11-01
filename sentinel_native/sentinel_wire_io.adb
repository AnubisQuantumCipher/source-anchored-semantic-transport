with Interfaces.C;
with System;
with Sentinel_Policy; use Sentinel_Policy;

package body Sentinel_Wire_IO is
   use type Interfaces.C.long;
   type U32 is mod 2 ** 32 with Size => 32;
   type Bytes is array (Positive range <>) of Octet with Component_Size => 8;
   Input : Bytes (1 .. Input_Cap + 1) := [others => 0];
   Output : Bytes (1 .. Output_Size) := [others => 0];
   Item : Session;
   Held, Observed : Identity;
   Roster : Questions := [others => <>];
   Evidence : Claims := [others => <>];
   Initial_Candidate : Digest := Zero_Digest;
   Total_Claims : Claim_Count := 0;
   Total_Probes : Probe_Count := 0;
   Q_Seen, Answers_Seen : Probe_Count := 0;
   Claims_Seen : Claim_Count := 0;
   Loaded, Position, Payload_Length : Natural := 0;
   Out_Position : Positive := 1;
   Reason : Natural := 0;
   Invoked, Finished, Output_Failed : Boolean := False;
   type Phase_Kind is
     (Need_Init, Need_Questions, Need_Claims, Need_Bind,
      Need_Answers, Need_Request, After_Request);
   Phase : Phase_Kind := Need_Init;

   function Read_C
     (Fd : Interfaces.C.int; Buffer : System.Address;
      Count : Interfaces.C.size_t) return Interfaces.C.long
     with Import, Convention => C, External_Name => "read";
   function Write_C
     (Fd : Interfaces.C.int; Buffer : System.Address;
      Count : Interfaces.C.size_t) return Interfaces.C.long
     with Import, Convention => C, External_Name => "write";

   procedure Refuse (Code : Natural) is
   begin
      if Reason = 0 then
         Reason := Code;
      end if;
   end Refuse;

   procedure Load_Input is
      Amount : Interfaces.C.long;
      Requested : Natural;
   begin
      for Attempt in 1 .. Input_Cap + 2 loop
         Requested := Natural'Min (4_096, Input'Length - Loaded);
         Amount := Read_C (0, Input (Loaded + 1)'Address,
                           Interfaces.C.size_t (Requested));
         if Amount < 0 or else Amount > Interfaces.C.long (Requested) then
            Refuse (23);
            return;
         elsif Amount = 0 then
            return;
         end if;
         Loaded := Loaded + Natural (Amount);
         if Loaded > Input_Cap then
            Refuse (13);
            return;
         end if;
      end loop;
      Refuse (23);
   end Load_Input;

   function Get_Byte return Natural is
      Value : Natural := 0;
   begin
      if Position = 0 or else Position > Loaded then
         Refuse (18);
      else
         Value := Natural (Input (Position));
         Position := Position + 1;
      end if;
      return Value;
   end Get_Byte;

   function Get_U16 return Natural is
      High : constant Natural := Get_Byte;
      Low : constant Natural := Get_Byte;
   begin
      return High * 256 + Low;
   end Get_U16;

   function Get_U32 return U32 is
      Value : U32 := 0;
   begin
      for I in 1 .. 4 loop
         Value := Value * 256 + U32 (Get_Byte);
      end loop;
      return Value;
   end Get_U32;

   function Bounded_U32 (Maximum : Natural) return Natural is
      Value : constant U32 := Get_U32;
   begin
      if Value > U32 (Maximum) then
         Refuse (20);
         return 0;
      end if;
      return Natural (Value);
   end Bounded_U32;

   function Get_Digest return Digest is
      Value : Digest := Zero_Digest;
   begin
      for I in Value'Range loop
         Value (I) := Octet (Get_Byte);
      end loop;
      return Value;
   end Get_Digest;

   function Get_Identity return Identity is
      Value : Identity;
   begin
      for K in Pin_Kind loop
         Value.Hashes (K) := Get_Digest;
      end loop;
      Value.Source_Bytes := Bounded_U32 (Max_Source);
      Value.Reading_Bytes := Bounded_U32 (Max_Reading);
      Value.Region_Start := Bounded_U32 (Max_Reading);
      Value.Region_End := Bounded_U32 (Max_Reading);
      if Value.Source_Bytes = 0 or else Value.Region_Start >= Value.Region_End
        or else Value.Region_End > Value.Reading_Bytes
        or else Value.Region_End - Value.Region_Start > Max_Region
      then
         Refuse (20);
      end if;
      return Value;
   end Get_Identity;

   procedure Check_Native is
   begin
      if Fatal (Item) then
         Refuse (21);
      end if;
   end Check_Native;

   procedure Parse_Init is
      C, P : Natural;
   begin
      Held := Get_Identity;
      C := Get_U16;
      P := Get_U16;
      Initial_Candidate := Get_Digest;
      if C not in 1 .. Max_Claims or else P not in 1 .. Max_Probes then
         Refuse (20);
      end if;
      if Reason = 0 then
         Total_Claims := C;
         Total_Probes := P;
         Phase := Need_Questions;
      end if;
   end Parse_Init;

   procedure Parse_Question is
      Ordinal : constant Natural := Get_U16;
      Subject : constant Natural := Get_U16;
      Input_Pin : constant Digest := Get_Digest;
      Expected : constant Digest := Get_Digest;
   begin
      if Ordinal not in 1 .. Total_Probes
        or else Subject not in 1 .. Total_Claims then
         Refuse (20);
      elsif Ordinal /= Q_Seen + 1 then
         Refuse (17);
      else
         Roster (Ordinal) := (Subject, Input_Pin, Expected);
         Q_Seen := Q_Seen + 1;
         if Q_Seen = Total_Probes then
            Initialize (Item, Held, Roster, Total_Claims, Total_Probes,
                        Initial_Candidate);
            Check_Native;
            Phase := Need_Claims;
         end if;
      end if;
   end Parse_Question;

   function Get_Link return Source_Link is
      Kind : constant Natural := Get_Byte;
      Anchor : constant Digest := Get_Digest;
      First : constant Natural := Bounded_U32 (Max_Source);
      Last : constant Natural := Bounded_U32 (Max_Source);
      Value : Source_Link;
   begin
      if Kind > 1 then
         Refuse (20);
      else
         Value := (Representation'Val (Kind), Anchor, First, Last);
      end if;
      return Value;
   end Get_Link;

   procedure Parse_Claim is
      Ordinal : constant Natural := Get_U16;
      Documentary : constant Natural := Get_Byte;
      Count : constant Natural := Get_Byte;
      Value : Claim;
   begin
      if Ordinal not in 1 .. Total_Claims or else Documentary > 3
        or else Count > Max_Links then
         Refuse (20);
      elsif Payload_Length /= 4 + 41 * Count then
         Refuse (16);
      elsif Ordinal /= Claims_Seen + 1 then
         Refuse (17);
      else
         Value.Documentary := Documentary_State'Val (Documentary);
         Value.Count := Count;
         for L in 1 .. Count loop
            Value.Evidence (L) := Get_Link;
         end loop;
         if Reason = 0 then
            Evidence (Ordinal) := Value;
            Claims_Seen := Claims_Seen + 1;
            if Claims_Seen = Total_Claims then
               Phase := Need_Bind;
            end if;
         end if;
      end if;
   end Parse_Claim;

   procedure Parse_Bind is
      Context, Adjudication : Natural;
   begin
      Observed := Get_Identity;
      Context := Get_Byte;
      Adjudication := Get_Byte;
      if Context > 1 or else Adjudication > 1 then
         Refuse (20);
      end if;
      if Reason = 0 then
         Bind_Source (Item, Observed, Evidence, Context = 1,
                      Adjudication = 1);
         Check_Native;
         Phase := Need_Answers;
      end if;
   end Parse_Bind;

   procedure Parse_Answer is
      Ordinal : constant Natural := Get_U16;
      Candidate : constant Digest := Get_Digest;
      Actual : constant Digest := Get_Digest;
      Receipt : constant Digest := Get_Digest;
      Obstruction : constant Natural := Get_Byte;
   begin
      if Ordinal not in 1 .. Total_Probes or else Obstruction > 3 then
         Refuse (20);
      elsif Ordinal /= Answers_Seen + 1 then
         Refuse (17);
      else
         Record_Answer (Item, Ordinal, Observed, Candidate, Actual, Receipt,
                        Blocker'Val (Obstruction));
         Check_Native;
         Answers_Seen := Accepted_Count (Item);
         if Answers_Seen = Total_Probes then
            Phase := Need_Request;
         end if;
      end if;
   end Parse_Answer;

   function Get_Mask return Failure_Mask is
      Value : Failure_Mask := [others => [others => False]];
      Byte : Natural;
   begin
      for B in 0 .. 255 loop
         Byte := Get_Byte;
         for Bit in 0 .. 7 loop
            Value (B / 32 + 1, (B mod 32) * 8 + Bit + 1) :=
              (Byte / (2 ** (7 - Bit))) mod 2 = 1;
         end loop;
      end loop;
      return Value;
   end Get_Mask;

   procedure Parse_Refine is
      Candidate : constant Digest := Get_Digest;
      Repair : constant Digest := Get_Digest;
      Parents : constant Failure_Mask := Get_Mask;
   begin
      Begin_Refinement (Item, Candidate, Repair, Parents);
      Check_Native;
      if Reason = 0 then
         Evidence := [others => <>];
         Claims_Seen := 0;
         Answers_Seen := 0;
         Phase := Need_Claims;
      end if;
   end Parse_Refine;

   function Allowed (Opcode : Natural) return Boolean is
     (case Phase is
        when Need_Init => Opcode = 1,
        when Need_Questions => Opcode = 2,
        when Need_Claims => Opcode = 3,
        when Need_Bind => Opcode = 4,
        when Need_Answers => Opcode in 5 | 7,
        when Need_Request => Opcode = 7,
        when After_Request => Opcode in 6 | 8);

   function Length_Valid (Opcode, Length : Natural) return Boolean is
     (case Opcode is
        when 1 => Length = 340,
        when 2 => Length = 68,
        when 3 => Length in 4 .. 660 and then (Length - 4) mod 41 = 0,
        when 4 => Length = 306,
        when 5 => Length = 99,
        when 6 => Length = 320,
        when 7 | 8 => Length = 0,
        when others => False);

   procedure Dispatch (Opcode : Natural) is
   begin
      case Opcode is
         when 1 => Parse_Init;
         when 2 => Parse_Question;
         when 3 => Parse_Claim;
         when 4 => Parse_Bind;
         when 5 => Parse_Answer;
         when 6 => Parse_Refine;
         when 7 =>
            Request_Qualification (Item);
            Check_Native;
            Phase := After_Request;
         when 8 =>
            if Position /= Loaded + 1 then
               Refuse (19);
            else
               Finished := True;
            end if;
         when others => Refuse (15);
      end case;
   end Dispatch;

   procedure Parse_Frame is
      Opcode, Payload_End : Natural;
      Raw_Length : U32;
   begin
      if Position > Loaded then
         Refuse (22);
         return;
      elsif Loaded - Position + 1 < 5 then
         Refuse (18);
         return;
      end if;
      Opcode := Get_Byte;
      Raw_Length := Get_U32;
      if Opcode not in 1 .. 8 then
         Refuse (15);
      elsif Raw_Length > 660 then
         Refuse (16);
      elsif not Length_Valid (Opcode, Natural (Raw_Length)) then
         Refuse (16);
      elsif not Allowed (Opcode) then
         Refuse (17);
      elsif Natural (Raw_Length) > Loaded - (Position - 1) then
         Refuse (18);
      else
         Payload_Length := Natural (Raw_Length);
         Payload_End := Position + Payload_Length;
         Dispatch (Opcode);
         if Reason = 0 and then Position /= Payload_End then
            Refuse (16);
         end if;
      end if;
   end Parse_Frame;

   procedure Parse_Input is
   begin
      if Loaded < 8 then
         Refuse (18);
      elsif Input (1 .. 4) /= Bytes'[83, 84, 78, 49] then
         Refuse (10);
      elsif Input (5) /= 1 then
         Refuse (11);
      elsif Input (6) /= 0 or else Input (7) /= 0 or else Input (8) /= 0 then
         Refuse (12);
      else
         Position := 9;
         for Operation in 1 .. Operation_Cap loop
            Parse_Frame;
            exit when Reason /= 0 or else Finished;
         end loop;
         if Reason = 0 and then not Finished then
            Refuse (14);
         end if;
      end if;
   end Parse_Input;

   procedure Put_Byte (Value : Natural) is
   begin
      if Value > 255 or else Out_Position > Output'Last then
         Output_Failed := True;
      else
         Output (Out_Position) := Octet (Value);
         Out_Position := Out_Position + 1;
      end if;
   end Put_Byte;

   procedure Put_U16 (Value : Natural) is
   begin
      if Value > 65_535 then
         Output_Failed := True;
      else
         Put_Byte (Value / 256);
         Put_Byte (Value mod 256);
      end if;
   end Put_U16;

   procedure Put_U32 (Value : Natural) is
   begin
      Put_Byte ((Value / 16_777_216) mod 256);
      Put_Byte ((Value / 65_536) mod 256);
      Put_Byte ((Value / 256) mod 256);
      Put_Byte (Value mod 256);
   end Put_U32;

   procedure Put_Digest (Value : Digest) is
   begin
      for B of Value loop
         Put_Byte (Natural (B));
      end loop;
   end Put_Digest;

   procedure Put_Identity (Value : Identity) is
   begin
      for K in Pin_Kind loop
         Put_Digest (Value.Hashes (K));
      end loop;
      Put_U32 (Value.Source_Bytes);
      Put_U32 (Value.Reading_Bytes);
      Put_U32 (Value.Region_Start);
      Put_U32 (Value.Region_End);
   end Put_Identity;

   procedure Put_Mask (Value : Failure_Mask) is
      Byte : Natural;
   begin
      for R in Round_Id loop
         for B in 0 .. 31 loop
            Byte := 0;
            for Bit in 0 .. 7 loop
               if Value (R, B * 8 + Bit + 1) then
                  Byte := Byte + 2 ** (7 - Bit);
               end if;
            end loop;
            Put_Byte (Byte);
         end loop;
      end loop;
   end Put_Mask;

   procedure Put_History is
   begin
      for C in Claim_Id loop
         if Initialized (Item) and then C <= Total_Claims then
            Put_Byte (Documentary_State'Pos (Documentary_Of (Item, C)));
         else
            Put_Byte (3);
         end if;
      end loop;
      Put_Mask (Failure_History (Item));
      for R in Round_Id loop
         for P in Probe_Id loop
            Put_Byte (Answer_Result'Pos (Result_Of (Item, R, P)));
         end loop;
      end loop;
   end Put_History;

   procedure Put_Session is
      Empty : constant Identity := (others => <>);
   begin
      if Initialized (Item) then
         Put_Identity (Identity_Of (Item));
         Put_Digest (Candidate_Of (Item));
         Put_Byte (Current_Round (Item));
         Put_U16 (Total_Claims);
         Put_U16 (Total_Probes);
         Put_U16 (Accepted_Count (Item));
         Put_U16 (Failure_Count (Item));
      else
         Put_Identity (Empty);
         Put_Digest (Zero_Digest);
         Put_Byte (0);
         for I in 1 .. 4 loop
            Put_U16 (0);
         end loop;
      end if;
   end Put_Session;

   procedure Classification (Disposition, Code : out Natural) is
   begin
      if Reason /= 0 then
         Disposition := 0;
         Code := 3;
      elsif Initialized (Item) and then Finished
        and then State_Of (Item) = Qualified_For_Q and then Eligible (Item)
        and then Qualification_Requested (Item) then
         Disposition := 2;
         Code := 0;
      else
         Disposition := 1;
         Code := 2;
         if State_Of (Item) = Rejected then
            Reason := 2;
         elsif State_Of (Item) = Challenged then
            Reason := 3;
         else
            Reason := 1;
         end if;
      end if;
   end Classification;

   procedure Format_Output (Disposition : Natural) is
   begin
      Put_Byte (83); Put_Byte (84); Put_Byte (82); Put_Byte (49);
      Put_Byte (1);
      Put_Byte (Disposition);
      Put_U16 (Reason);
      Put_Session;
      Put_Byte (0);
      Put_Byte ((if Disposition = 2 then 1 else 0));
      if Initialized (Item) then
         Put_Byte (Interpretation_State'Pos (State_Of (Item)));
         Put_Byte (1);
      else
         Put_Byte (255);
         Put_Byte (0);
      end if;
      Put_History;
      if Out_Position /= Output_Size + 1 then
         Output_Failed := True;
      end if;
   end Format_Output;

   procedure Write_Output (OK : out Boolean) is
      Written : Natural := 0;
      Amount : Interfaces.C.long;
   begin
      OK := False;
      for Attempt in 1 .. Output_Size loop
         Amount := Write_C (1, Output (Written + 1)'Address,
                           Interfaces.C.size_t (Output_Size - Written));
         if Amount <= 0
           or else Amount > Interfaces.C.long (Output_Size - Written) then
            return;
         end if;
         Written := Written + Natural (Amount);
         if Written = Output_Size then
            OK := True;
            return;
         end if;
      end loop;
   end Write_Output;

   procedure Run (Exit_Code : out Natural) is
      Disposition : Natural;
      Written : Boolean;
   begin
      if Invoked then
         Exit_Code := 3;
         return;
      end if;
      Invoked := True;
      Load_Input;
      if Reason = 0 then
         Parse_Input;
      end if;
      Classification (Disposition, Exit_Code);
      Format_Output (Disposition);
      if Output_Failed then
         Exit_Code := 3;
      else
         Write_Output (Written);
         if not Written then
            Exit_Code := 3;
         end if;
      end if;
   end Run;
end Sentinel_Wire_IO;

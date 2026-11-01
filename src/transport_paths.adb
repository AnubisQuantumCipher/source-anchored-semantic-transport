package body Transport_Paths with SPARK_Mode is
   function Advance
     (G : Graph; From : Node_Ref; Position : Child_Position) return Node_Ref
   is
   begin
      if From = 0 or else Position > G.Nodes (From).Degree then
         return 0;
      end if;
      return G.Nodes (From).Children (Position);
   end Advance;

   function Trace (G : Graph; Choices : Path; Length : Path_Length)
      return Path_Trace
   is
      Result : Path_Trace := [others => 0];
   begin
      Result := [Result with delta 0 => G.Root];
      for I in 1 .. Length loop
         Result := [Result with delta I =>
           Advance (G, Result (I - 1), Choices (I))];
         pragma Loop_Invariant (Result (0) = G.Root);
         pragma Loop_Invariant
           (for all J in 0 .. I => Result (J) <= G.Count);
         pragma Loop_Invariant
           (for all J in 1 .. I =>
             Result (J) = Advance (G, Result (J - 1), Choices (J)));
         pragma Loop_Invariant
           (for all J in 0 .. I =>
             (if Result (J) > 0 then Result (J) + J <= G.Root));
         pragma Loop_Invariant
           (for all J in I + 1 .. Max_Nodes => Result (J) = 0);
      end loop;
      return Result;
   end Trace;

   function Follow (G : Graph; Choices : Path; Length : Path_Length)
      return Node_Ref
   is
      Steps : constant Path_Trace := Trace (G, Choices, Length);
   begin
      return Steps (Length);
   end Follow;

   procedure Same_Step_Observation
     (Original, Candidate : Graph; Map : Node_Map; At_Node : Node_Ref)
   with Ghost, Global => null, Always_Terminates,
     Pre => Preserves (Original, Candidate, Map) and then
       At_Node <= Original.Count,
     Post => Same_Observation
       (Original, At_Node, Candidate, Image (Map, At_Node))
   is
   begin
      if At_Node > 0 then
         pragma Assert (All_Nodes (Original, Candidate, Map));
         pragma Assert (Node_Preserved (Original, Candidate, Map, At_Node));
         pragma Assert (Image (Map, At_Node) = Map (At_Node));
         pragma Assert
           (Original.Nodes (At_Node).Tag =
            Candidate.Nodes (Map (At_Node)).Tag);
         pragma Assert
           (Original.Nodes (At_Node).Size =
            Candidate.Nodes (Map (At_Node)).Size);
         pragma Assert
           (Original.Nodes (At_Node).Degree =
            Candidate.Nodes (Map (At_Node)).Degree);
         pragma Assert
           (for all J in 1 .. Original.Nodes (At_Node).Size =>
              Original.Data ((Original.Nodes (At_Node).First + J) - 1) =
              Candidate.Data ((Candidate.Nodes (Map (At_Node)).First + J) - 1));
      else
         pragma Assert (Image (Map, At_Node) = 0);
      end if;
   end Same_Step_Observation;

   procedure Prove_Step
     (Original, Candidate : Graph; Map : Node_Map;
      From : Node_Ref; Position : Child_Position)
   with Ghost, Global => null, Always_Terminates,
     Pre => Preserves (Original, Candidate, Map) and then
       From <= Original.Count,
     Post => Advance (Candidate, Image (Map, From), Position) =
       Image (Map, Advance (Original, From, Position))
   is
   begin
      if From > 0 then
         pragma Assert (All_Nodes (Original, Candidate, Map));
         pragma Assert (Node_Preserved (Original, Candidate, Map, From));
      end if;
   end Prove_Step;

   procedure Same_At_Equal
     (Left, Right : Graph; A, B, C, D : Node_Ref)
   with Ghost, Global => null, Always_Terminates,
     Pre => Well_Formed (Left) and then Well_Formed (Right) and then
       A <= Left.Count and then B <= Right.Count and then
       C <= Left.Count and then D <= Right.Count and then
       A = C and then B = D and then
       Same_Observation (Left, A, Right, B),
     Post => Same_Observation (Left, C, Right, D)
   is
   begin
      null;
   end Same_At_Equal;

   procedure Prove_Path_Preservation
     (Original, Candidate : Graph; Map : Node_Map;
      Choices : Path; Length : Path_Length)
   is
      Left : constant Path_Trace := Trace (Original, Choices, Length);
      Right : constant Path_Trace := Trace (Candidate, Choices, Length);
   begin
      pragma Assert (Right (0) = Image (Map, Left (0)));
      for I in 1 .. Length loop
         pragma Loop_Invariant
           (for all J in 0 .. I - 1 => Right (J) = Image (Map, Left (J)));
         Prove_Step (Original, Candidate, Map, Left (I - 1), Choices (I));
         pragma Assert (Right (I) = Image (Map, Left (I)));
      end loop;
      pragma Assert
        (for all I in 0 .. Length => Right (I) = Image (Map, Left (I)));
      Same_Step_Observation (Original, Candidate, Map, Left (Length));
      pragma Assert (Follow (Original, Choices, Length) = Left (Length));
      pragma Assert (Follow (Candidate, Choices, Length) = Right (Length));
      pragma Assert (Right (Length) = Image (Map, Left (Length)));
      pragma Assert (Well_Formed (Original) and then Well_Formed (Candidate));
      pragma Assert (Left (Length) <= Original.Count);
      pragma Assert (Image (Map, Left (Length)) <= Candidate.Count);
      pragma Assert (Follow (Original, Choices, Length) <= Original.Count);
      pragma Assert (Follow (Candidate, Choices, Length) <= Candidate.Count);
      Same_At_Equal
        (Original, Candidate, Left (Length), Image (Map, Left (Length)),
         Follow (Original, Choices, Length),
         Follow (Candidate, Choices, Length));
   end Prove_Path_Preservation;
end Transport_Paths;

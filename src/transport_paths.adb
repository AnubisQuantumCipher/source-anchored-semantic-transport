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
      Result (0) := G.Root;
      for I in 1 .. Length loop
         Result (I) := Advance (G, Result (I - 1), Choices (I));
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
         pragma Assert (Node_Preserved (Original, Candidate, Map, From));
      end if;
   end Prove_Step;

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
      if Left (Length) > 0 then
         pragma Assert
           (Node_Preserved (Original, Candidate, Map, Left (Length)));
      end if;
   end Prove_Path_Preservation;
end Transport_Paths;

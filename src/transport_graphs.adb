package body Transport_Graphs with SPARK_Mode is
   function Node_Preserved
     (Original, Candidate : Graph; Map : Node_Map; I : Node_Id)
      return Boolean
   is
      Left  : constant Node := Original.Nodes (I);
      Right : constant Node := Candidate.Nodes (Map (I));
   begin
      return Left.Tag = Right.Tag and then Left.Size = Right.Size and then
        Left.Degree = Right.Degree and then
        (for all J in 1 .. Left.Size =>
          Original.Data ((Left.First + J) - 1) =
          Candidate.Data ((Right.First + J) - 1)) and then
        (for all J in 1 .. Left.Degree =>
          Map (Left.Children (J)) = Right.Children (J));
   end Node_Preserved;

   function Images_Cover
     (Original, Candidate : Graph; Map : Node_Map) return Boolean
   is
      Hit : array (Node_Id) of Boolean := [others => False];
      Covered : Boolean := True;
   begin
      for I in 1 .. Original.Count loop
         pragma Loop_Invariant
           (for all K in 1 .. Candidate.Count =>
              Hit (K) = (for some T in 1 .. I - 1 => Map (T) = K));
         if Map (I) in Node_Id and then Map (I) <= Candidate.Count then
            Hit (Map (I)) := True;
         end if;
      end loop;
      pragma Assert
        (for all K in 1 .. Candidate.Count =>
           Hit (K) = (for some T in 1 .. Original.Count => Map (T) = K));
      for J in 1 .. Candidate.Count loop
         pragma Loop_Invariant
           (Covered = (for all K in 1 .. J - 1 => Hit (K)));
         if not Hit (J) then
            Covered := False;
         end if;
      end loop;
      pragma Assert (Covered = (for all K in 1 .. Candidate.Count => Hit (K)));
      return Covered;
   end Images_Cover;

   function All_Nodes
     (Original, Candidate : Graph; Map : Node_Map) return Boolean
   is
      Nodes_Ok : Boolean := True;
   begin
      for I in 1 .. Original.Count loop
         pragma Loop_Invariant
           (Nodes_Ok =
              (for all K in 1 .. I - 1 =>
                 Node_Preserved (Original, Candidate, Map, K)));
         if not Node_Preserved (Original, Candidate, Map, I) then
            Nodes_Ok := False;
         end if;
      end loop;
      return Nodes_Ok;
   end All_Nodes;

   function Preserves (Original, Candidate : Graph; Map : Node_Map)
      return Boolean
   is
      Well : constant Boolean := Valid_Map (Original, Candidate, Map);
   begin
      if not Well then
         return False;
      end if;
      return (Map (Original.Root) = Candidate.Root) and then
        All_Nodes (Original, Candidate, Map) and then
        Images_Cover (Original, Candidate, Map);
   end Preserves;

   procedure Check
     (Original, Candidate : Graph; Map : Node_Map; Result : out Status)
   is
   begin
      if Preserves (Original, Candidate, Map) then
         Result := Ok;
      else
         Result := Graph_Mismatch;
      end if;
   end Check;
end Transport_Graphs;

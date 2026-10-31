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
          Original.Data (Left.First + J - 1) =
          Candidate.Data (Right.First + J - 1)) and then
        (for all J in 1 .. Left.Degree =>
          Map (Left.Children (J)) = Right.Children (J));
   end Node_Preserved;

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

with Interfaces.C;

package body Transport_Bound_Eval_IO with SPARK_Mode => Off is
   use Interfaces.C;
   type Raw_Buffer is array (1 .. Max_Frame + 1) of unsigned_char
     with Convention => C;

   function Read_Bounded
     (Path : char_array; Data : out Raw_Buffer; Capacity : size_t;
      Used : out size_t) return int
   with Import, Convention => C, External_Name => "transport_bound_read_frame";

   procedure Read_Frame
     (Path : String; Wire : out Frame_Buffer; Length : out Frame_Length;
      Valid : out Boolean)
   is
      Data : Raw_Buffer;
      Used : size_t;
      Read_Status : int;
   begin
      Wire := [others => 0];
      Length := 0;
      Valid := False;
      if Path'Length = 0 or Path'Length >= 4_096 then
         return;
      end if;
      for Element of Path loop
         if Element = Character'Val (0) then
            return;
         end if;
      end loop;
      Read_Status := Read_Bounded (To_C (Path), Data, Data'Length, Used);
      if Read_Status /= 0 or else Used > Max_Frame then
         return;
      end if;
      Length := Natural (Used);
      for I in 1 .. Length loop
         Wire (I) := Byte (Data (I));
      end loop;
      Valid := True;
   end Read_Frame;
end Transport_Bound_Eval_IO;

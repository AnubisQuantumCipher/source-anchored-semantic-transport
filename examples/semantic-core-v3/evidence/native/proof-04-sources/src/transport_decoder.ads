with Transport_Types; use Transport_Types;

package Transport_Decoder with SPARK_Mode is
   procedure Decode
     (Wire : Wire_Buffer; Length : Wire_Length; Output : out Source_Buffer;
      Used : out Source_Length; Result : out Status)
   with Global => null, Always_Terminates,
     Post => (if Result /= Ok then
                Used = 0 and then (for all B of Output => B = 0));

   procedure Check
     (Wire : Wire_Buffer; Length : Wire_Length; Source : Source_Buffer;
      Size : Source_Length; Output : out Source_Buffer;
      Used : out Source_Length; Result : out Status)
   with Global => null, Always_Terminates,
     Post =>
       (if Result = Ok then Used = Size and then
          (for all J in 1 .. Size => Output (J) = Source (J))
        else Used = 0 and then (for all B of Output => B = 0));
end Transport_Decoder;

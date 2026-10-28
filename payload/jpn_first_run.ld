SECTIONS
{
  .zero_length 0x00166d64 : { KEEP(*(.zero_length)) }
  .hook_response 0x00166df8 : { KEEP(*(.hook_response)) }
  .response_payload 0x001669e4 : { KEEP(*(.response_payload)) }
}

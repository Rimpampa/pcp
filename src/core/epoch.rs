/// The PCP epoch field
///
/// This type implements the core time validity mechanism
/// employed by the PCP protocol.
/// It represents the time, relative to the **PCP server** POV, passed
/// between a response packet an the other.
///
/// It's usage and checks are explained in the [Section 8.5 of RFC6887].
///
/// [Section 8.5 of RFC6887]: https://www.rfc-editor.org/rfc/rfc6887.html#section-8.5
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Epoch(pub u32);

impl Epoch {
    /// Validate the new [`Epoch`] according to the `previous` one and time `elapsed` since then
    ///
    /// The validation consists in making sure that:
    /// 1) the **server** time is always increasing within a small tolerance window
    ///    (because of possible routing delays)
    /// 2) the **client** time increases at the same rate as the **server** one
    ///
    /// The `previous` parameter is used to compute the time elapsed on the **server**
    /// while `elapsed` paramter is the elapsed time according to the **client**
    pub fn validate_epoch(&self, previous: Epoch, elapsed: u32) -> bool {
        // RFC 6887, Section 8.5:
        // > Whenever a client receives a PCP response, the client validates the
        // > received Epoch Time value according to the procedure below, using
        // > integer arithmetic

        // RFC 6887, Section 8.5:
        // > If this is the first PCP response the client has received from
        // > this PCP server, the Epoch Time value is treated as necessarily
        // > valid, otherwise:
        // NOTE: the function assumes this is not the first response

        // RFC 6887, Section 8.5:
        // > If the current PCP server Epoch time (curr_server_time) is less
        // > than the previously received PCP server Epoch time
        // > (prev_server_time) by more than one second, then the client
        // > treats the Epoch time as obviously invalid (time should not go
        // > backwards).  The server Epoch time apparently going backwards
        // > by *up to* one second is not deemed invalid, so that minor
        // > packet reordering on the path from PCP server to PCP client
        // > does not trigger a cascade of unnecessary mapping renewals.
        if self.0 < previous.0.saturating_sub(1) {
            return false;
        }

        // RFC 6887, Section 8.5:
        // > The client computes the difference between its
        // > current local time (curr_client_time) and the
        // > time the previous PCP response was received from this PCP
        // > server (prev_client_time):
        // > client_delta = curr_client_time - prev_client_time;
        let client_delta = elapsed;

        // RFC 6887, Section 8.5:
        // > The client computes the difference between the
        // > current PCP server Epoch time (curr_server_time) and the
        // > previously received Epoch time (prev_server_time):
        // > server_delta = curr_server_time - prev_server_time;
        let server_delta = self.0.saturating_sub(previous.0);

        // RFC 6887, Section 8.5:
        // > If client_delta+2 < server_delta - server_delta/16
        // > or server_delta+2 < client_delta - client_delta/16,
        // > then the client treats the Epoch Time value as invalid,
        // > else the client treats the Epoch Time value as valid.
        !(client_delta + 2 < server_delta - server_delta / 16
            || server_delta + 2 < client_delta - client_delta / 16)
    }
}

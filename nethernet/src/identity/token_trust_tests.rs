use super::*;
use crate::identity::jwk::{Jwk, JwkSet};
use std::time::{Duration, UNIX_EPOCH};

const VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.ZNrl8i3EhnyNI8JsYxCXFzbT7hobsgFGGW1oJPdXLOaG2UD9twmwJRQQ9vJ6G-Oxa_v7QCp0xC2z-paPwuMApx_NYcVr_QII81f-jPIfuh4ZUnAAOF1fLi4c-FaSVlKum5GzTaTWtnQ-qD1RMxJ7oSjuTX8r8ymNT6pAW6FUuFE1An4B1AP2yRt9kb8zERcTZhsp30EPB3gjL_P_tVMyqTb0MBTlMzTZAECyzEvDFbaveXxAeAb7_-g80GtOg_7EUbPSgH1nyb8ez2od_p42kP9mIdnaKDgvC4PzjCUlkQ5nLWy-4YUQVoGIxTMHCt3YTIy0JNqmOBgSlgTDqcN0ig";

const NO_KID: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.2Vagw7vlJZvw7zSLbf4ir66_wE3k7CkG6LZ5JEihx6HGXy7raTq0YgUEru98l-PNFG7imWBXCLcIJn2D9xBH0eXjel5b-HTTx1dlTSdn83fBENqBsTOtVi0ZHjfOTsxZfxqb4ik72CX0CldjuGv3Y-Q__dBy5YAvR2nqE_psHykjwbrJvlzHirQ9h4o8uLlDS0tgIYG75J7zXmqh-jraZty-4x-sf6GHHRhyKAEpYIFuAzTP5GJkt9qLSRo-kcwL9RL2U5B7DFiNhsW8N9J5MUEfB-NB3Y-dJgUP6zsiTG7XdFKvaGRd5mB01jjaJIHP_3W1oQMLNJOpmRq5TT4Iyw";

const NO_KID_SECOND_KEY: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.V2DuPxS-3YA65x-FyPHggxAOadCTYMbRGx6gXshaLphhRA-VN4vgm3p-YULLeQgHO4353AVuE0sOxy412ikqStG8ZAk0j0dU35vBvIzkSZ9NPoSJQlkz30tA4B_TdiRKITrmfAvWY_wjQl0hQrbeZX4I1Zs-GQLcqGabBTpHtpkylo40ykaUeTizgZfG2VjVlwG_CfWNJ6Xd6beigzN4riDefRnUVDfUJT_fvP_jJKPNkesmMuKJWCu7skOuxYFcsYqKkKB5PiXyxvp7oUAHuaarX96_cVNiFtGnbutAzjRi9i_fxwUooKBwzFUeET_AiF187-sCxqM7Fffn8Abr0Q";

const UNKNOWN_KID: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS05In0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.W1FDQT0QfEG_MEP-q_q_hFxHnKXNmcfbBe2uJis3uIuX4UXC-inL5-nN0g9lc0cR4jBthYpZSvLdBD9PNX394pRxZz9iqszw1FxGfYuwgaFk78O154kXGq9nI7m5q71Mmx9Fcoq4DhMEvaaxAjUnk-sS_8l-QSbrs70AYK7ZYG80PRIziVPObSMYvcvCOKu19w2NnLgq2TLJATelYoY_hQLY5m1uzk1AD2hdlAXhEDI-KGYQ-5Ne25FAV2Lt6y-8vmX0SPvrcL08guZkmSQX_cX6nnYGTBrBsScAxcXDQzx2XBobiM_Cx_Tud6raStNJkABTxdbyZ3PvYE-abCDqzA";

const TAMPERED: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiTWFsbG9yeSIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.ZNrl8i3EhnyNI8JsYxCXFzbT7hobsgFGGW1oJPdXLOaG2UD9twmwJRQQ9vJ6G-Oxa_v7QCp0xC2z-paPwuMApx_NYcVr_QII81f-jPIfuh4ZUnAAOF1fLi4c-FaSVlKum5GzTaTWtnQ-qD1RMxJ7oSjuTX8r8ymNT6pAW6FUuFE1An4B1AP2yRt9kb8zERcTZhsp30EPB3gjL_P_tVMyqTb0MBTlMzTZAECyzEvDFbaveXxAeAb7_-g80GtOg_7EUbPSgH1nyb8ez2od_p42kP9mIdnaKDgvC4PzjCUlkQ5nLWy-4YUQVoGIxTMHCt3YTIy0JNqmOBgSlgTDqcN0ig";

const WRONG_KEY: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.njK8T0xrXeurdRv3jLwNFVFWm7akKuk6_cqDbHLbbjzDs5kHknkVo9JZTiYs_cjZ5srES8xSwxVa8ZGpZSm_szPmzaSV8xJpjAV5gY7BdMhoPrct72PJU8sMAB6cVOq_5NpNecF55gzHdioNEPNp2RvIB9sbSQNub-gxK-T6Mg6-W0xeJVdJUeFcKZfgqQi6uGhGBge2oQmoDNqMvtAAIB_5bUwbzf0YPJsZ4eFRtHSJeUuGh003GZHv4dMkDvRCnKPG9WPwzGa8uVM8VDHD2QgS-D8zoMFJ5Q_nq9HU2ICDmu8mnGD2g2-3eFLzH3gJKyKsrvnl3zqxaMEGPFdOng";

const HS256: &str = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.g7ZWFqd1ft3IHHkDQUqt7HXY9OJV7jWq6V-0eUror-1Xiy7ciu_z_2x6nwCrubuC2zLDl5wnIm1mK3ipzFIFmrQ5d6U2tNO0KjRFFVncjWhiy5HLBlPvbE1Ku26ADHoqWAler4-YxjxZZCfnecwUmEQq07s_G0z3KrC5e9cD5Qq3_rFosK87kSzUMAzTHLySDjTy103-pRPukmJfET73j_awLNm1E1f2rEYKPmRr48mYolQc5mwODzhq__xfE3nXJNkF-Ck3bJJe_r9sXyH1YmOAMkhBVDsb8SbS-GzzflxR9AxPye713UTwVTBdoSkDNeKveuC7hfIWz6wRk2624Q";

const ES384: &str = "eyJhbGciOiJFUzM4NCIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.egihbfnCSc59EB4KqS000Q4Vw73Y6WvSOwPdn-2bcG4whepTki4ImvCqYyxwcrw25vUML0Me5BBB8BSf58k9UW_msWMq2OwRcELyHVAz99XNtlP_ZPXiOMURDmJVrvXXKLh258tmjUrJrE1d9wRegxJaXMNGCpuuPx6ZV78aEHA1PBZXpS2xT5LEE4gTQheVyGL0eBMlslOuS49mNwWb0CaFuVks5l8MvXHgD05Zm-uVdGHYyeL6gDkXenqNE5Wt8_wKFBPq2v9jFS14gsB3bVBmaE09mp3OLMREZEQntQ9RFFW6RcXI2CwIeTyV8BVCG0GuBsfzGUdEjbbpwDnvqw";

const NO_SUBJECT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJ4aWQiOiIyNTM1NDAwMDAwMDAwMDAxIiwieG5hbWUiOiJBbGV4IiwiY3BrIjoiTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVtMXlKdmNNRkhOTVRLWmFlQzFaNmtkVzU3a2JIL1F4ZUNQK0FFUjdXYnVycGk2WGhXSUhJQXRzUHhZV0JQZXVFaU9pdFhieGR2cnZFWHk0MnhhaXYvQTE3Ty9CNGRwQ3E3Y1FTT2ZRNEpZVm1VbXgrNnZQSUIxTktDVkFOa096ciIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.SDZFFn3GXjoQQ1aBIJaHRGMmLQoTBYPc3cD-MUxP99i-0WXpXbAhX1MDHpEFlEkqTltzj9tXYaAV7d7gxpDYnsX967zdKk1C6MmEcOCDu9HK62D4LCtr8uqvX248oaCNGFPJT7NQRUSTs_JuxzLdtcGw7EEi-tQMpQROU4PUuarENqehXjMiMrfRKm24GdBZ34ziR2qqxmacn0cLlYFpnXW1IstYXzMbayLai9Ws1B63_todrcJR2KbxdlZVFxQg1xQkkS5k2gGunI4cGll3fhdndlWjvYcTYMhR4zy8l5EHDl9udt5VU3EAEFdGgjFBkvbZ9SwDs_UsUATvM90qVQ";

const WRONG_ISSUER: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tLyIsImF1ZCI6ImFwaTovL2F1dGgtbWluZWNyYWZ0LXNlcnZpY2VzL211bHRpcGxheWVyIiwic3ViIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhpZCI6IjI1MzU0MDAwMDAwMDAwMDEiLCJ4bmFtZSI6IkFsZXgiLCJjcGsiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRW0xeUp2Y01GSE5NVEtaYWVDMVo2a2RXNTdrYkgvUXhlQ1ArQUVSN1didXJwaTZYaFdJSElBdHNQeFlXQlBldUVpT2l0WGJ4ZHZydkVYeTQyeGFpdi9BMTdPL0I0ZHBDcTdjUVNPZlE0SllWbVVteCs2dlBJQjFOS0NWQU5rT3pyIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.0bMTF8PCfaszAdUEzd5l5EPA-xL9SMrw-M4UaxDfxPglDYL2DN6ZI-UVhXb6lzXsa0sQboVgYa8k-BazxJZKUfR9PLKMbS2OnAUAce-FA83SyEGBVc1Hyp2Ze5JKXw_o0LzU5bHB2hhZSrk7tnE-JvHvTixmjruCs5Wf4fHPrFXebQgIVtpspWc0HYWsrrf0Y1Uff_x62jfjAet2Gki-X_TMCUo-yR6zB7iZ8Ez2GH-LrxoFvgpOQhAZx7ebz5e0_msPrUzKFIWKtQfqVM-X-aS--s7CspOHUW6e7oU_0N5nzflZQRBMoUlaCFFIcarTslOFi5_RcuvBTTetPvxCZg";

const AUD_STRING: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.ZNrl8i3EhnyNI8JsYxCXFzbT7hobsgFGGW1oJPdXLOaG2UD9twmwJRQQ9vJ6G-Oxa_v7QCp0xC2z-paPwuMApx_NYcVr_QII81f-jPIfuh4ZUnAAOF1fLi4c-FaSVlKum5GzTaTWtnQ-qD1RMxJ7oSjuTX8r8ymNT6pAW6FUuFE1An4B1AP2yRt9kb8zERcTZhsp30EPB3gjL_P_tVMyqTb0MBTlMzTZAECyzEvDFbaveXxAeAb7_-g80GtOg_7EUbPSgH1nyb8ez2od_p42kP9mIdnaKDgvC4PzjCUlkQ5nLWy-4YUQVoGIxTMHCt3YTIy0JNqmOBgSlgTDqcN0ig";

const AUD_ARRAY: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjpbImFwaTovL290aGVyIiwiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiXSwic3ViIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhpZCI6IjI1MzU0MDAwMDAwMDAwMDEiLCJ4bmFtZSI6IkFsZXgiLCJjcGsiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRW0xeUp2Y01GSE5NVEtaYWVDMVo2a2RXNTdrYkgvUXhlQ1ArQUVSN1didXJwaTZYaFdJSElBdHNQeFlXQlBldUVpT2l0WGJ4ZHZydkVYeTQyeGFpdi9BMTdPL0I0ZHBDcTdjUVNPZlE0SllWbVVteCs2dlBJQjFOS0NWQU5rT3pyIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjQxMDI0NDQ4MDB9.F8-09fib1fuAjYPIBQWjw2PSdXz4HJJ84sKrItE3mY9xlQMTZZdltSEmETyCeBU-hwNQIu2vOzeVYoxsZWOow2DoexL8ohCDCofIMOvcIO2j0Qtjsw_-5hLqUOlxfw4pyAv7OnryvIme3b6zBZmNd3ckVP1OQlAL9uZR3mzPv0Pb_g_hNLFvPymbJWQ36IPHZEpZyoSU85kt8Jsv7WzgWPhcf_ikr6zTHYYq1Q24qKx3PNIPMkVgcOKl6i8y4_yolekFABb2kIHoFFxshRR6OPie7HslpZUlFVCcmgPpAO72cJ7hV4TynAsdALD1drpLKGDaYBn8BPnxqn-hE-RWsg";

const WRONG_AUD: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vb3RoZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6NDEwMjQ0NDgwMH0.j7tMKLlCU_bRl9ejvPOrAP16FuZyJB5I84os2vSzuh8SmAl3O2ohX_BleKi65V7tbkxQ3Wemf3hhQ9uSFUocl0pKtj3RF30EbQ4Yzv8MSEPKzKBVMYYjXL5iaBF2c0K3OXT2cy0uNVgA850iRwFEh3MYDVARR5KcOSv3yKNxQTXZidyh9IHCEWdNLWHDd0TKA1ZAatIRB0qpWL3SQOVnzI2Xr1tiWmrPXPGIwc-CP_oeOMA7SsXHAAZuAw7yCDGzYKXAsLOW9EcFqN8sOaQib00Zg2JrcOzQCRNnhFHF3zip0yGSoUxPAMVMiqtdbcSdcpT4iEWyu8i1fDTQ3XJC1w";

const EXPIRED: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGhvcml6YXRpb24uZnJhbmNoaXNlLm1pbmVjcmFmdC1zZXJ2aWNlcy5uZXQvIiwiYXVkIjoiYXBpOi8vYXV0aC1taW5lY3JhZnQtc2VydmljZXMvbXVsdGlwbGF5ZXIiLCJzdWIiOiIyNTM1NDAwMDAwMDAwMDAxIiwieGlkIjoiMjUzNTQwMDAwMDAwMDAwMSIsInhuYW1lIjoiQWxleCIsImNwayI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFbTF5SnZjTUZITk1US1phZUMxWjZrZFc1N2tiSC9ReGVDUCtBRVI3V2J1cnBpNlhoV0lISUF0c1B4WVdCUGV1RWlPaXRYYnhkdnJ2RVh5NDJ4YWl2L0ExN08vQjRkcENxN2NRU09mUTRKWVZtVW14KzZ2UElCMU5LQ1ZBTmtPenIiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTAwMDAwMDAwMH0.g5BEcBNg42KsXyzVTQdY26SwxyBKA8gqNUaEu3Cp-GbK2MwBFWZi8EOyUcoN796vUHIS6CaEeOe63GeBs8WrbDebRkKzaWgzvvS_wZqDo79ebjH17zG_rOmCJWq_22KHxiN2Zi4wzP7cK1PzFaKIuxZU_328goazWQCyvG0Rg9l8hWXBM--idGFAMS62FI2aH4ZDddq2zBDQEbkZWa241ZohalgK5p9mhyTxkDfPFZFJ81CRIeE-b2AhSHUHWlRGEOKChgn4URpCkcLRN_gD60jOEZugXSKU3QdpnX1s-44mPWiwSAYde7hKqjkc_7HICrB58O-n3Qr2eVVQO6bQDQ";

const FINGERPRINT_SIGNATURE: &str = "eyJhbGciOiJFUzM4NCJ9..kjOysp8c0lflCbPtaHnJC5V5_81w8COEJ25eAORqZ0ZOV1-8jNyyK7qz7bZ2ku1ujam344N2fQLOp6Rgzk8oKFvTOGdfGE5btoqh-qGR5wbFFcEYlxvVfyXUsqxFKRxo";

const KEY_ONE: &str = r#"{"kty":"RSA","kid":"key-1","n":"4XRseZxjQjHSgp3aGkjCc5dhncuTxvu2V_yFc2eW4VXrXW1T7KJAccS9cdWM_1SOVk5E0T51M-rdnGv0ME0wZYZ1JwCPc0If5EJr8gjFH48gqEkPhA4d8CHqnPIzqnkUC58KzJTO5ZAiFAaY_LbEeQJF7-4-Afb2UQ6uftWNT59xW9bBlaYC6tdjR451YEoCCQYsGZ4BYUMwn-4cDTd2yHOfX1D-1B_DieHHSFuJfQMIy5IZMw1zDb6nQS6pP5bUEwkJkhraI5E3onJJzt88KeFaHiOeRpBPhQdv7v_LZqIyFASMZB_hLXGafCC5L--9hrwZADZzCysJLEHUHVdnNQ","e":"AQAB"}"#;

const KEY_TWO: &str = r#"{"kty":"RSA","kid":"key-2","n":"vZWHy0WxaZneDhToKD8SBAOKze2rMCdQvO-9yNu4lMwJoi8qniGssK-UtxUpgPeU_VusMGzwK-IZsLv9i4jH6JfhI17C7Ad5ZJdpou5ovNu9BSHwGrftjg849n52PsYrxQ-BXgrpfCNY1fXZYkUiuF5qqyHq2Sl1R2IBFtuyBipw5655ReonTa7WytGyhlf39YsdnCq0yr3tM9g3vYJj-p1lAqvq8VzGgXFsPZhLaZp5BkYc0lhSAr4natEqdQZuuLdOjHf_Yx7pNn3_3rv8ik_qjRmn_DNbT9-k0_sD1EwZ1lftOrQDIfg2Jovuk-HaF9psfdP5klmyHQbDWksNxw","e":"AQAB"}"#;

const FINGERPRINT_LINE: &str =
    "a=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\n";

const XUID: &str = "2535400000000001";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

fn key(json: &str) -> Jwk {
    serde_json::from_str(json).unwrap()
}

fn both_keys() -> TokenTrust {
    TokenTrust::Minecraft(JwkSet {
        keys: vec![key(KEY_ONE), key(KEY_TWO)],
    })
}

fn first_key_only() -> TokenTrust {
    TokenTrust::Minecraft(JwkSet {
        keys: vec![key(KEY_ONE)],
    })
}

fn identity(token: &str, fingerprints: &str) -> Identity {
    Identity {
        idp: Idp {
            domain: String::new(),
            protocol: "default".to_string(),
        },
        assertion: Assertion {
            token: token.to_string(),
            fingerprints: fingerprints.to_string(),
        },
    }
}

fn offer(token: &str, fingerprints: &str, fingerprint_line: &str) -> String {
    format!(
        "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=identity:{}\r\n{}",
        identity(token, fingerprints).to_base64().unwrap(),
        fingerprint_line
    )
}

fn claims_of(token: &str, trust: &TokenTrust) -> Result<Claims> {
    trust.claims(&identity(token, ""), now())
}

fn refusal(token: &str, trust: &TokenTrust) -> String {
    match claims_of(token, trust).unwrap_err() {
        IdentityError::Untrusted(reason) => reason,
        other => panic!("expected Untrusted, got {:?}", other),
    }
}

#[test]
fn a_token_signed_by_a_published_key_yields_its_claims() {
    let claims = claims_of(VALID_TOKEN, &both_keys()).unwrap();

    assert_eq!(claims.subject(), Some(XUID));
    assert_eq!(claims.issuer(), Some(MINECRAFT_ISSUER));
    assert_eq!(claims.audience(), vec![MINECRAFT_AUDIENCE]);
    assert_eq!(claims.xuid(), Some(XUID));
    assert_eq!(claims.display_name(), Some("Alex"));
}

#[test]
fn player_info_carries_the_xuid_and_display_name_of_a_trusted_token() {
    let claims = claims_of(VALID_TOKEN, &both_keys()).unwrap();

    let player = PlayerInfo::new(claims, "net-1".to_string(), None);

    assert_eq!(player.xuid.as_deref(), Some(XUID));
    assert_eq!(player.display_name.as_deref(), Some("Alex"));
    assert_eq!(player.network_id, "net-1");
    assert!(player.client_public_key().is_ok());
}

#[test]
fn a_token_without_a_kid_is_tried_against_every_key() {
    assert!(claims_of(NO_KID, &first_key_only()).is_ok());
    assert!(claims_of(NO_KID_SECOND_KEY, &both_keys()).is_ok());
}

#[test]
fn a_token_without_a_kid_signed_by_no_published_key_is_refused() {
    assert_eq!(
        refusal(NO_KID_SECOND_KEY, &first_key_only()),
        "the token is not signed by the issuer"
    );
}

#[test]
fn a_token_naming_an_unpublished_kid_is_refused() {
    assert_eq!(
        refusal(UNKNOWN_KID, &both_keys()),
        "the token names a key that is not published"
    );
}

#[test]
fn a_token_whose_kid_selects_only_another_key_is_refused() {
    let trust = TokenTrust::Minecraft(JwkSet {
        keys: vec![key(KEY_TWO)],
    });

    assert_eq!(
        refusal(VALID_TOKEN, &trust),
        "the token names a key that is not published"
    );
}

#[test]
fn a_token_with_a_tampered_payload_is_refused() {
    assert_eq!(
        refusal(TAMPERED, &both_keys()),
        "the token is not signed by the issuer"
    );
}

#[test]
fn a_token_signed_by_a_different_key_than_its_kid_names_is_refused() {
    assert_eq!(
        refusal(WRONG_KEY, &both_keys()),
        "the token is not signed by the issuer"
    );
}

#[test]
fn an_hs256_token_is_refused() {
    assert_eq!(refusal(HS256, &both_keys()), "expected RS256, got HS256");
}

#[test]
fn an_es384_token_is_refused() {
    assert_eq!(refusal(ES384, &both_keys()), "expected RS256, got ES384");
}

#[test]
fn a_signed_token_without_a_subject_is_refused() {
    assert_eq!(
        refusal(NO_SUBJECT, &both_keys()),
        "the token carries no subject"
    );
}

#[test]
fn a_signed_token_from_another_issuer_is_refused() {
    assert_eq!(
        refusal(WRONG_ISSUER, &both_keys()),
        "the token was issued by someone else"
    );
}

#[test]
fn an_audience_given_as_a_string_is_accepted() {
    assert!(claims_of(AUD_STRING, &both_keys()).is_ok());
}

#[test]
fn an_audience_given_as_an_array_is_accepted() {
    let claims = claims_of(AUD_ARRAY, &both_keys()).unwrap();

    assert_eq!(claims.audience(), vec!["api://other", MINECRAFT_AUDIENCE]);
}

#[test]
fn a_signed_token_for_another_audience_is_refused() {
    assert_eq!(
        refusal(WRONG_AUD, &both_keys()),
        "the token is addressed to another audience"
    );
}

#[test]
fn an_expired_signed_token_is_refused() {
    assert_eq!(refusal(EXPIRED, &both_keys()), "the token has expired");
}

#[test]
fn a_signed_token_is_accepted_under_any_trust_without_checking_its_signature() {
    assert!(claims_of(TAMPERED, &TokenTrust::Any).is_ok());
    assert!(claims_of(WRONG_ISSUER, &TokenTrust::Any).is_ok());
}

#[test]
fn an_offer_with_a_trusted_token_and_a_matching_fingerprint_signature_validates() {
    let sdp = offer(VALID_TOKEN, FINGERPRINT_SIGNATURE, FINGERPRINT_LINE);

    let claims = validate_sdp(&sdp, &both_keys(), now()).unwrap();

    assert_eq!(claims.subject(), Some(XUID));
    assert_eq!(claims.display_name(), Some("Alex"));
}

#[test]
fn an_offer_whose_fingerprint_differs_from_the_signed_one_is_refused() {
    let sdp = offer(
        VALID_TOKEN,
        FINGERPRINT_SIGNATURE,
        "a=fingerprint:sha-256 00:11\r\n",
    );

    let error = validate_sdp(&sdp, &both_keys(), now()).unwrap_err();

    assert!(matches!(error, IdentityError::FingerprintMismatch));
}

#[test]
fn an_offer_with_a_tampered_token_is_refused_before_its_fingerprints_are_checked() {
    let sdp = offer(TAMPERED, FINGERPRINT_SIGNATURE, FINGERPRINT_LINE);

    let error = validate_sdp(&sdp, &both_keys(), now()).unwrap_err();

    assert!(matches!(error, IdentityError::Untrusted(_)));
}

#[test]
fn an_offer_with_a_trusted_token_but_no_published_keys_is_refused() {
    let sdp = offer(VALID_TOKEN, FINGERPRINT_SIGNATURE, FINGERPRINT_LINE);

    let error = validate_sdp(&sdp, &TokenTrust::Minecraft(JwkSet::default()), now()).unwrap_err();

    assert!(matches!(error, IdentityError::Untrusted(_)));
}

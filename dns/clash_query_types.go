package dns

import (
	icontext "github.com/ProjectClash/Clash/context"

	D "github.com/miekg/dns"
)

type QueryTypes struct {
	SVCB   *bool
	Others *bool
}

func (q QueryTypes) answersSVCB() bool { return q.SVCB != nil && *q.SVCB }

func (h *ResolverEnhancer) AnswersSVCB() bool { return h.queryTypes.answersSVCB() }

func withQueryTypes(q QueryTypes, next handler) handler {
	if q.SVCB == nil && q.Others == nil {
		return next
	}
	refusesOthers := q.Others != nil && !*q.Others
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		if len(r.Question) > 0 {
			switch r.Question[0].Qtype {
			case D.TypeA, D.TypeAAAA:
			case D.TypeSVCB, D.TypeHTTPS:
				if q.SVCB != nil {
					if !*q.SVCB {
						return handleMsgWithEmptyAnswer(r), nil
					}
				} else if refusesOthers {
					return handleMsgWithEmptyAnswer(r), nil
				}
			default:
				if refusesOthers {
					return handleMsgWithEmptyAnswer(r), nil
				}
			}
		}
		return next(ctx, r)
	}
}
